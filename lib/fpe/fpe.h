#ifndef HEXLOCK_FPE_H
#define HEXLOCK_FPE_H

#include "../include/hexlock.h"

#include <stddef.h>
#include <stdint.h>

/*
 * FPE encrypt/decrypt functions for each PII type that uses format-preserving
 * encryption. All functions:
 *   - key: 32-byte AES-256 key, extracted by router from hexlock_ctx_t
 *   - src/src_len: input string and length
 *   - dst: caller-provided output buffer, must be at least src_len+1 bytes
 *   - format is preserved: dst will be the same length as src
 *   - return HEXLOCK_OK on success, HEXLOCK_ERR_INTERNAL on failure
 *
 * fpe_digits_only() is static internal to fpe.c and not exposed here.
 * Each function below corresponds directly to a named regex capture group
 * in hexlock_patterns.h, so no format re-detection is needed at call site.
 */

/*
 * Phone (NANP) — one function per sub-format matching PATTERN_PHONE_*
 */
hexlock_err_t fpe_encrypt_phone_paren(const uint8_t *key, const char *src,
                                      size_t src_len, char *dst);
hexlock_err_t fpe_decrypt_phone_paren(const uint8_t *key, const char *src,
                                      size_t src_len, char *dst);

hexlock_err_t fpe_encrypt_phone_dash(const uint8_t *key, const char *src,
                                     size_t src_len, char *dst);
hexlock_err_t fpe_decrypt_phone_dash(const uint8_t *key, const char *src,
                                     size_t src_len, char *dst);

hexlock_err_t fpe_encrypt_phone_dot(const uint8_t *key, const char *src,
                                    size_t src_len, char *dst);
hexlock_err_t fpe_decrypt_phone_dot(const uint8_t *key, const char *src,
                                    size_t src_len, char *dst);

hexlock_err_t fpe_encrypt_phone_space(const uint8_t *key, const char *src,
                                      size_t src_len, char *dst);
hexlock_err_t fpe_decrypt_phone_space(const uint8_t *key, const char *src,
                                      size_t src_len, char *dst);

hexlock_err_t fpe_encrypt_phone_bare(const uint8_t *key, const char *src,
                                     size_t src_len, char *dst);
hexlock_err_t fpe_decrypt_phone_bare(const uint8_t *key, const char *src,
                                     size_t src_len, char *dst);

/*
 * SSN — single dashed format: NNN-NN-NNNN
 */
hexlock_err_t fpe_encrypt_ssn(const uint8_t *key, const char *src,
                              size_t src_len, char *dst);
hexlock_err_t fpe_decrypt_ssn(const uint8_t *key, const char *src,
                              size_t src_len, char *dst);

/*
 * Credit card — digits with optional space/dash separators
 */
hexlock_err_t fpe_encrypt_credit_card(const uint8_t *key, const char *src,
                                      size_t src_len, char *dst);
hexlock_err_t fpe_decrypt_credit_card(const uint8_t *key, const char *src,
                                      size_t src_len, char *dst);

/*
 * IP address (IPv4 only) — FPE on 4 octets with radix 256, output is valid IPv4.
 * NOTE: output length may differ from input (e.g. 192.168.1.1 -> 247.31.8.200).
 * Caller must provide dst buffer of at least 16 bytes regardless of src_len.
 */
hexlock_err_t fpe_encrypt_ip_address(const uint8_t *key, const char *src,
                                     size_t src_len, char *dst);
hexlock_err_t fpe_decrypt_ip_address(const uint8_t *key, const char *src,
                                     size_t src_len, char *dst);

/*
 * Passport (US) — leading 1-2 alpha chars are passthrough, digits are FPE
 * payload
 */
hexlock_err_t fpe_encrypt_passport(const uint8_t *key, const char *src,
                                   size_t src_len, char *dst);
hexlock_err_t fpe_decrypt_passport(const uint8_t *key, const char *src,
                                   size_t src_len, char *dst);

/*
 * Routing number — 9 bare digits
 */
hexlock_err_t fpe_encrypt_routing_number(const uint8_t *key, const char *src,
                                         size_t src_len, char *dst);
hexlock_err_t fpe_decrypt_routing_number(const uint8_t *key, const char *src,
                                         size_t src_len, char *dst);

/*
 * Bank account — 8-17 bare digits
 */
hexlock_err_t fpe_encrypt_bank_account(const uint8_t *key, const char *src,
                                       size_t src_len, char *dst);
hexlock_err_t fpe_decrypt_bank_account(const uint8_t *key, const char *src,
                                       size_t src_len, char *dst);

/*
 * Driver's license — leading 1-2 alpha chars are passthrough, digits are FPE
 * payload
 */
hexlock_err_t fpe_encrypt_drivers_license(const uint8_t *key, const char *src,
                                          size_t src_len, char *dst);
hexlock_err_t fpe_decrypt_drivers_license(const uint8_t *key, const char *src,
                                          size_t src_len, char *dst);

/*
 * GitHub classic tokens — one pair per prefix, all delegate to the same
 * internal helper in fpe.c with different prefix strings. Body is 36
 * chars, radix 62 [A-Za-z0-9].
 */
hexlock_err_t fpe_encrypt_github_ghp(const uint8_t *key, const char *src, size_t src_len, char *dst);
hexlock_err_t fpe_decrypt_github_ghp(const uint8_t *key, const char *src, size_t src_len, char *dst);

hexlock_err_t fpe_encrypt_github_gho(const uint8_t *key, const char *src, size_t src_len, char *dst);
hexlock_err_t fpe_decrypt_github_gho(const uint8_t *key, const char *src, size_t src_len, char *dst);

hexlock_err_t fpe_encrypt_github_ghu(const uint8_t *key, const char *src, size_t src_len, char *dst);
hexlock_err_t fpe_decrypt_github_ghu(const uint8_t *key, const char *src, size_t src_len, char *dst);

hexlock_err_t fpe_encrypt_github_ghs(const uint8_t *key, const char *src, size_t src_len, char *dst);
hexlock_err_t fpe_decrypt_github_ghs(const uint8_t *key, const char *src, size_t src_len, char *dst);

hexlock_err_t fpe_encrypt_github_ghr(const uint8_t *key, const char *src, size_t src_len, char *dst);
hexlock_err_t fpe_decrypt_github_ghr(const uint8_t *key, const char *src, size_t src_len, char *dst);

/*
 * AWS access key ID — AKIA prefix (4 chars), body 16 chars radix 36 [A-Z0-9]
 * AWS secret key — no prefix, full 40 chars radix 64 [A-Za-z0-9/+]
 */
hexlock_err_t fpe_encrypt_aws_access_key(const uint8_t *key, const char *src, size_t src_len, char *dst);
hexlock_err_t fpe_decrypt_aws_access_key(const uint8_t *key, const char *src, size_t src_len, char *dst);

hexlock_err_t fpe_encrypt_aws_secret_key(const uint8_t *key, const char *src, size_t src_len, char *dst);
hexlock_err_t fpe_decrypt_aws_secret_key(const uint8_t *key, const char *src, size_t src_len, char *dst);

/*
 * Anthropic keys — api03 and oat01 prefixes, both 48-char radix 62 bodies.
 * Same logic as GitHub wrappers, different prefix string.
 */
hexlock_err_t fpe_encrypt_anthropic_api(const uint8_t *key, const char *src, size_t src_len, char *dst);
hexlock_err_t fpe_decrypt_anthropic_api(const uint8_t *key, const char *src, size_t src_len, char *dst);

hexlock_err_t fpe_encrypt_anthropic_oat(const uint8_t *key, const char *src, size_t src_len, char *dst);
hexlock_err_t fpe_decrypt_anthropic_oat(const uint8_t *key, const char *src, size_t src_len, char *dst);

/*
 * JWT — three segment structure handled internally, see fpe.c for detail.
 */
//hexlock_err_t fpe_encrypt_jwt(const uint8_t *key, const char *src, size_t src_len, char *dst);
//hexlock_err_t fpe_decrypt_jwt(const uint8_t *key, const char *src, size_t src_len, char *dst);
#endif /* HEXLOCK_FPE_H */
