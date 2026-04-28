#include "fpe.h"

#include "../fpe/fast.h"
#include "../include/hexlock.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/*
 * Maximum digit payload length and mask entries.
 * Matches transformed[64] in hexlock_token_record_t.
 */
#define FPE_MAX_LEN 64
#define FPE_MAX_MASK 64  // XXX: if any regex matches get close to this we have to make this larger

/*
 * Records the position and character of a non-digit passthrough character.
 * Used to reconstruct the original format after FPE.
 */
typedef struct {
	size_t pos;
	char ch;
} fpe_mask_entry_t;

/*
 * helper function
 * parses ipV4 so we don't have to add in heavy library calls
 */
static int
parse_ipv4(const char *src, size_t src_len, uint8_t octets[4])
{
    size_t i = 0;
    for (int octet = 0; octet < 4; octet++) {
        if (octet > 0) {
            if (i >= src_len || src[i] != '.') return -1;
            i++;
        }
        if (i >= src_len || src[i] < '0' || src[i] > '9') return -1;
        int val = 0;
        while (i < src_len && src[i] >= '0' && src[i] <= '9') {
            val = val * 10 + (src[i++] - '0');
            if (val > 255) return -1;
        }
        octets[octet] = (uint8_t)val;
    }
    return 0;
}

/*
 * helper function
 * formats ipV4 so we don't have to add in heavy library calls
 */
static int format_ipv4(char *dst, size_t dst_size, const uint8_t octets[4]) {
	size_t pos = 0;
	for (int octet = 0; octet < 4; octet++) {
		if (octet > 0) {
			if (pos + 1 >= dst_size) {
				return -1;
			}
			dst[pos++] = '.';
		}
		uint8_t val = octets[octet];
		if (val >= 100) {
			if (pos + 1 >= dst_size) {
				return -1;
			}
			dst[pos++] = '0' + val / 100;
		}
		if (val >= 10) {
			if (pos + 1 >= dst_size) {
				return -1;
			}
			dst[pos++] = '0' + (val % 100) / 10;
		}
		if (pos + 1 >= dst_size) {
			return -1;
		}
		dst[pos++] = '0' + val % 10;
	}
	dst[pos] = '\0';
	return 0;
}

/*
 * Separate src into a digit payload array (values 0-9, not ASCII)
 * and a mask of passthrough characters with their original positions.
 * Returns 0 on success, -1 if buffers would overflow.
 */
static int extract_digits(const char *src, size_t src_len, uint8_t *digits,
                          size_t *digit_count, fpe_mask_entry_t *mask,
                          size_t *mask_count) {
	size_t di = 0, mi = 0;

	for (size_t i = 0; i < src_len; i++) {
		char c = src[i];
		if (c >= '0' && c <= '9') {
			if (di >= FPE_MAX_LEN)
				return -1;
			digits[di++] = (uint8_t)(c - '0');
		} else {
			if (mi >= FPE_MAX_MASK)
				return -1;
			mask[mi].pos = i;
			mask[mi].ch = c;
			mi++;
		}
	}

	*digit_count = di;
	*mask_count = mi;
	return 0;
}

/*
 * Reinsert passthrough characters into dst around the transformed digit
 * payload. digits[] contains transformed digit values (0-9, not ASCII). dst
 * must be at least src_len+1 bytes.
 */
static int reinsert_mask(char *dst, size_t src_len, const uint8_t *digits,
                         size_t digit_count, const fpe_mask_entry_t *mask,
                         size_t mask_count) {
	size_t di = 0, mi = 0;

	for (size_t i = 0; i < src_len; i++) {
		if (mi < mask_count && mask[mi].pos == i) {
			dst[i] = mask[mi].ch;
			mi++;
		} else {
			if (digits[di] > 9)
				return -1;
			dst[i] = (char)('0' + digits[di++]);
		}
	}
	dst[src_len] = '\0';
	(void)digit_count;
	return 0;
}

/*
 * Build a 4-byte big-endian tweak from a PII type enum value.
 * This ensures the same digit string encrypts differently per PII domain.
 */
static void make_type_tweak(hexlock_pii_type_t type, uint8_t tweak[4]) {
	uint32_t v = (uint32_t)type;
	tweak[0] = (uint8_t)((v >> 24) & 0xFF);
	tweak[1] = (uint8_t)((v >> 16) & 0xFF);
	tweak[2] = (uint8_t)((v >> 8) & 0xFF);
	tweak[3] = (uint8_t)(v & 0xFF);
}

/*
 * Core internal FPE primitive. Not exposed in fpe.h.
 *
 * Strips non-digit characters from src, records their positions,
 * runs FAST encrypt or decrypt on the digit payload, then reinserts
 * the passthrough characters. Format is always preserved.
 *
 * key:     32-byte AES-256 key
 * type:    PII type, used to derive a domain-separation tweak
 * src:     input string (ASCII)
 * src_len: length of src, not including any null terminator
 * dst:     output buffer, must be >= src_len+1 bytes
 * encrypt: 1 to encrypt, 0 to decrypt
 */
static hexlock_err_t fpe_digits_only(const uint8_t *key,
                                     hexlock_pii_type_t type, const char *src,
                                     size_t src_len, char *dst, int encrypt) {
	uint8_t digits[FPE_MAX_LEN];
	uint8_t out_digits[FPE_MAX_LEN];
	fpe_mask_entry_t mask[FPE_MAX_MASK];
	size_t digit_count, mask_count;

	if (!key || !src || !dst)
		return HEXLOCK_ERR_INTERNAL;
	if (src_len == 0 || src_len > FPE_MAX_LEN)
		return HEXLOCK_ERR_INTERNAL;

	if (extract_digits(src, src_len, digits, &digit_count, mask,
	                   &mask_count) != 0)
		return HEXLOCK_ERR_INTERNAL;

	if (digit_count == 0)
		return HEXLOCK_ERR_INTERNAL;

	/* derive tweak from PII type for domain separation */
	uint8_t tweak[4];
	make_type_tweak(type, tweak);

	/* initialise FAST for radix-10, word length = digit payload length */
	fast_params_t params = {0};
	params.security_level = 128;
	if (calculate_recommended_params(&params, 10, (uint32_t)digit_count) !=
	    0)
		return HEXLOCK_ERR_INTERNAL;

	fast_context_t *fctx = NULL;
	if (fast_init(&fctx, &params, key) != 0)
		return HEXLOCK_ERR_INTERNAL;

	int rc;
	if (encrypt)
		rc = fast_encrypt(fctx, tweak, sizeof(tweak), digits,
		                  out_digits, digit_count);
	else
		rc = fast_decrypt(fctx, tweak, sizeof(tweak), digits,
		                  out_digits, digit_count);

	fast_cleanup(fctx);

	if (rc != 0)
		return HEXLOCK_ERR_INTERNAL;

	if (reinsert_mask(dst, src_len, out_digits, digit_count, mask,
	                  mask_count) != 0) {
		return HEXLOCK_ERR_INTERNAL;
	}

	return HEXLOCK_OK;
}

/* -------------------------------------------------------------------------
 * Phone (NANP)
 * All five sub-formats go straight through fpe_digits_only.
 * The mask handles parens, dashes, dots, and spaces transparently.
 * ------------------------------------------------------------------------- */

hexlock_err_t fpe_encrypt_phone_paren(const uint8_t *key, const char *src,
                                      size_t src_len, char *dst) {
	return fpe_digits_only(key, HEXLOCK_PII_PHONE, src, src_len, dst, 1);
}
hexlock_err_t fpe_decrypt_phone_paren(const uint8_t *key, const char *src,
                                      size_t src_len, char *dst) {
	return fpe_digits_only(key, HEXLOCK_PII_PHONE, src, src_len, dst, 0);
}

hexlock_err_t fpe_encrypt_phone_dash(const uint8_t *key, const char *src,
                                     size_t src_len, char *dst) {
	return fpe_digits_only(key, HEXLOCK_PII_PHONE, src, src_len, dst, 1);
}
hexlock_err_t fpe_decrypt_phone_dash(const uint8_t *key, const char *src,
                                     size_t src_len, char *dst) {
	return fpe_digits_only(key, HEXLOCK_PII_PHONE, src, src_len, dst, 0);
}

hexlock_err_t fpe_encrypt_phone_dot(const uint8_t *key, const char *src,
                                    size_t src_len, char *dst) {
	return fpe_digits_only(key, HEXLOCK_PII_PHONE, src, src_len, dst, 1);
}
hexlock_err_t fpe_decrypt_phone_dot(const uint8_t *key, const char *src,
                                    size_t src_len, char *dst) {
	return fpe_digits_only(key, HEXLOCK_PII_PHONE, src, src_len, dst, 0);
}

hexlock_err_t fpe_encrypt_phone_space(const uint8_t *key, const char *src,
                                      size_t src_len, char *dst) {
	return fpe_digits_only(key, HEXLOCK_PII_PHONE, src, src_len, dst, 1);
}
hexlock_err_t fpe_decrypt_phone_space(const uint8_t *key, const char *src,
                                      size_t src_len, char *dst) {
	return fpe_digits_only(key, HEXLOCK_PII_PHONE, src, src_len, dst, 0);
}

hexlock_err_t fpe_encrypt_phone_bare(const uint8_t *key, const char *src,
                                     size_t src_len, char *dst) {
	return fpe_digits_only(key, HEXLOCK_PII_PHONE, src, src_len, dst, 1);
}
hexlock_err_t fpe_decrypt_phone_bare(const uint8_t *key, const char *src,
                                     size_t src_len, char *dst) {
	return fpe_digits_only(key, HEXLOCK_PII_PHONE, src, src_len, dst, 0);
}

/* -------------------------------------------------------------------------
 * SSN — NNN-NN-NNNN
 * Dashes are passthrough, 9 digits are the payload.
 * ------------------------------------------------------------------------- */

hexlock_err_t fpe_encrypt_ssn(const uint8_t *key, const char *src,
                              size_t src_len, char *dst) {
	return fpe_digits_only(key, HEXLOCK_PII_SSN, src, src_len, dst, 1);
}
hexlock_err_t fpe_decrypt_ssn(const uint8_t *key, const char *src,
                              size_t src_len, char *dst) {
	return fpe_digits_only(key, HEXLOCK_PII_SSN, src, src_len, dst, 0);
}

/* -------------------------------------------------------------------------
 * Credit card — 16 digits with optional space/dash separators
 * Separators are passthrough, 16 digits are the payload.
 * ------------------------------------------------------------------------- */

hexlock_err_t fpe_encrypt_credit_card(const uint8_t *key, const char *src,
                                      size_t src_len, char *dst) {
	return fpe_digits_only(key, HEXLOCK_PII_CREDIT_CARD, src, src_len, dst,
	                       1);
}
hexlock_err_t fpe_decrypt_credit_card(const uint8_t *key, const char *src,
                                      size_t src_len, char *dst) {
	return fpe_digits_only(key, HEXLOCK_PII_CREDIT_CARD, src, src_len, dst,
	                       0);
}

/* -------------------------------------------------------------------------
 * IP address (IPv4)
 * Parse dotted quad into 4 octet values (0-255), run FAST with radix 256
 * and word length 4, reformat as dotted quad. Preserves valid IPv4 format.
 * Small domain (2^32) is inherent to IPv4, not a regression.
 * Flag HEXLOCK_FLAG_FPE_PRESERVE_FORMAT (future) will control this behavior.
 * ------------------------------------------------------------------------- */
static hexlock_err_t fpe_ip(const uint8_t *key, const char *src, size_t src_len,
                            char *dst, int encrypt) {
	if (!key || !src || !dst)
		return HEXLOCK_ERR_INTERNAL;

	uint8_t octets[4];
	if (parse_ipv4(src, src_len, octets) != 0)
		return HEXLOCK_ERR_INTERNAL;

	uint8_t tweak[4];
	make_type_tweak(HEXLOCK_PII_IP_ADDRESS, tweak);

	fast_params_t params = {0};
	params.security_level = 128;
	if (calculate_recommended_params(&params, 256, 4) != 0) {
		return HEXLOCK_ERR_INTERNAL;
	}

	fast_context_t *fctx = NULL;
	if (fast_init(&fctx, &params, key) != 0) {
		return HEXLOCK_ERR_INTERNAL;
	}

	uint8_t out[4];
	int rc;
	if (encrypt)
		rc = fast_encrypt(fctx, tweak, sizeof(tweak), octets, out, 4);
	else
		rc = fast_decrypt(fctx, tweak, sizeof(tweak), octets, out, 4);

	fast_cleanup(fctx);

	if (rc != 0) {
		return HEXLOCK_ERR_INTERNAL;
	}

	if (format_ipv4(dst, 16, out) != 0) {
		return HEXLOCK_ERR_INTERNAL;
	}

	(void)src_len;
	return HEXLOCK_OK;
}

hexlock_err_t fpe_encrypt_ip_address(const uint8_t *key, const char *src,
                                     size_t src_len, char *dst) {
	return fpe_ip(key, src, src_len, dst, 1);
}
hexlock_err_t fpe_decrypt_ip_address(const uint8_t *key, const char *src,
                                     size_t src_len, char *dst) {
	return fpe_ip(key, src, src_len, dst, 0);
}

/* -------------------------------------------------------------------------
 * Passport (US) — 1-2 leading alpha chars + 6-9 digits
 * Alpha prefix is naturally passthrough in the mask since it is non-digit.
 * fpe_digits_only handles it with no special casing needed.
 * ------------------------------------------------------------------------- */

hexlock_err_t fpe_encrypt_passport(const uint8_t *key, const char *src,
                                   size_t src_len, char *dst) {
	return fpe_digits_only(key, HEXLOCK_PII_PASSPORT, src, src_len, dst, 1);
}
hexlock_err_t fpe_decrypt_passport(const uint8_t *key, const char *src,
                                   size_t src_len, char *dst) {
	return fpe_digits_only(key, HEXLOCK_PII_PASSPORT, src, src_len, dst, 0);
}

/* -------------------------------------------------------------------------
 * Routing number — exactly 9 bare digits, no separators
 * ------------------------------------------------------------------------- */

hexlock_err_t fpe_encrypt_routing_number(const uint8_t *key, const char *src,
                                         size_t src_len, char *dst) {
	return fpe_digits_only(key, HEXLOCK_PII_ROUTING_NUMBER, src, src_len,
	                       dst, 1);
}
hexlock_err_t fpe_decrypt_routing_number(const uint8_t *key, const char *src,
                                         size_t src_len, char *dst) {
	return fpe_digits_only(key, HEXLOCK_PII_ROUTING_NUMBER, src, src_len,
	                       dst, 0);
}

/* -------------------------------------------------------------------------
 * Bank account — 8-17 bare digits, no separators
 * ------------------------------------------------------------------------- */

hexlock_err_t fpe_encrypt_bank_account(const uint8_t *key, const char *src,
                                       size_t src_len, char *dst) {
	return fpe_digits_only(key, HEXLOCK_PII_BANK_ACCOUNT, src, src_len, dst,
	                       1);
}
hexlock_err_t fpe_decrypt_bank_account(const uint8_t *key, const char *src,
                                       size_t src_len, char *dst) {
	return fpe_digits_only(key, HEXLOCK_PII_BANK_ACCOUNT, src, src_len, dst,
	                       0);
}

/* -------------------------------------------------------------------------
 * Driver's license — 1-2 leading alpha chars + 6-8 digits
 * Same as passport: alpha prefix is naturally passthrough in the mask.
 * ------------------------------------------------------------------------- */

hexlock_err_t fpe_encrypt_drivers_license(const uint8_t *key, const char *src,
                                          size_t src_len, char *dst) {
	return fpe_digits_only(key, HEXLOCK_PII_DRIVERS_LICENSE, src, src_len,
	                       dst, 1);
}
hexlock_err_t fpe_decrypt_drivers_license(const uint8_t *key, const char *src,
                                          size_t src_len, char *dst) {
	return fpe_digits_only(key, HEXLOCK_PII_DRIVERS_LICENSE, src, src_len,
	                       dst, 0);
}
