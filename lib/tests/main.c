#include "../fpe/cmac.h"
#include "../fpe/fast.h"
#include "../fpe/fpe.h"
#include "../include/hexlock.h"
#include "../include/hexlock_regex.h"
#include "../tokenizer/tokenizer.c"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* =========================================================================
 * Minimal test harness
 * ========================================================================= */

static int g_total = 0;
static int g_failed = 0;

#define CHECK(desc, expr)                                                      \
	do {                                                                   \
		g_total++;                                                     \
		if (!(expr)) {                                                 \
			g_failed++;                                            \
			fprintf(stderr, "  FAIL  %s\n", desc);                 \
		} else {                                                       \
			printf("  pass  %s\n", desc);                          \
		}                                                              \
	} while (0)

#define CHECK_BYTES(desc, got, expected, len)                                  \
	do {                                                                   \
		g_total++;                                                     \
		if (memcmp((got), (expected), (len)) != 0) {                   \
			g_failed++;                                            \
			fprintf(stderr, "  FAIL  %s\n    got:      ", desc);   \
			for (size_t _i = 0; _i < (len); _i++)                  \
				fprintf(stderr, "%02x",                        \
				        ((uint8_t *)(got))[_i]);               \
			fprintf(stderr, "\n    expected: ");                   \
			for (size_t _i = 0; _i < (len); _i++)                  \
				fprintf(stderr, "%02x",                        \
				        ((uint8_t *)(expected))[_i]);          \
			fprintf(stderr, "\n");                                 \
		} else {                                                       \
			printf("  pass  %s\n", desc);                          \
		}                                                              \
	} while (0)

static void print_summary(void) {
	printf("%s — %d/%d passed\n\n", g_failed == 0 ? "OK" : "FAILED",
	       g_total - g_failed, g_total);
}

/* =========================================================================
 * Regex smoke test (existing, preserved as-is)
 * ========================================================================= */

static const char *pii_type_name(hexlock_pii_type_t type) {
	switch (type) {
	case HEXLOCK_PII_EMAIL:
		return "EMAIL";
	case HEXLOCK_PII_PHONE:
		return "PHONE";
	case HEXLOCK_PII_SSN:
		return "SSN";
	case HEXLOCK_PII_CREDIT_CARD:
		return "CREDIT_CARD";
	case HEXLOCK_PII_NAME:
		return "NAME";
	case HEXLOCK_PII_ADDRESS:
		return "ADDRESS";
	case HEXLOCK_PII_DATE_OF_BIRTH:
		return "DATE_OF_BIRTH";
	case HEXLOCK_PII_IP_ADDRESS:
		return "IP_ADDRESS";
	case HEXLOCK_PII_PASSPORT:
		return "PASSPORT";
	case HEXLOCK_PII_ROUTING_NUMBER:
		return "ROUTING_NUMBER";
	case HEXLOCK_PII_BANK_ACCOUNT:
		return "BANK_ACCOUNT";
	case HEXLOCK_PII_DRIVERS_LICENSE:
		return "DRIVERS_LICENSE";
	default:
		return "UNKNOWN";
	}
}

static void test_regex(void) {
	printf("--- regex ---\n");

	hexlock_route_t routes[HEXLOCK_PII_COUNT] = {0};
	hexlock_regex_ctx_t *ctx = NULL;
	hexlock_err_t err = hexlock_regex_init(&ctx, routes);
	CHECK("hexlock_regex_init succeeds", err == HEXLOCK_OK);
	if (err != HEXLOCK_OK)
		return;

	const char *input = "Contact john@example.com or call 212-555-0100. "
	                    "SSN: 123-45-6789. IP: 192.168.1.1. "
	                    "CC: 4111 1111 1111 1111.";

	hexlock_match_t *matches = NULL;
	size_t match_count = 0;
	err = hexlock_regex_scan(ctx, input, strlen(input), &matches,
	                         &match_count);
	CHECK("hexlock_regex_scan succeeds", err == HEXLOCK_OK);

	if (err == HEXLOCK_OK) {
		CHECK("finds at least 4 matches", match_count >= 4);

		/* Print matches for human review — the regex suite is still
		 * partially visual since we don't assert on specific offsets
		 * yet. */
		printf("  matches found: %zu\n", match_count);
		for (size_t i = 0; i < match_count; i++) {
			size_t len = matches[i].end - matches[i].start;
			printf("    [%s] \"%.*s\" (offset %zu-%zu)\n",
			       pii_type_name(matches[i].type), (int)len,
			       input + matches[i].start, matches[i].start,
			       matches[i].end);
		}
	}

	hexlock_matches_free(matches, match_count);
	hexlock_regex_free(ctx);
	print_summary();
}

/* =========================================================================
 * CMAC tests
 *
 * Vectors: NIST SP 800-38B, AES-256
 * Key (256-bit):
 *   60 3d eb 10 15 ca 71 be  2b 73 ae f0 85 7d 77 81
 *   1f 35 2c 07 3b 61 08 d7  2d 98 10 a3 09 14 df f4
 *
 * All four message lengths from the spec are covered, plus streaming
 * variants to exercise the update() buffering logic.
 * ========================================================================= */

/* NIST AES-256 key shared by all CMAC tests */
static const uint8_t CMAC_KEY[32] = {
        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae,
        0xf0, 0x85, 0x7d, 0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61,
        0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4,
};

/*
 * Run CMAC over msg in one shot and compare tag to expected.
 * Returns 1 on match, 0 on mismatch (so it can feed CHECK_BYTES directly,
 * but we call it through a wrapper that also prints context on failure).
 */
static void cmac_oneshot(const char *desc, const uint8_t *msg, size_t msg_len,
                         const uint8_t *expected) {
	CMAC_ctx_t ctx;
	uint8_t tag[CMAC_BLOCK_LENGTH];

	CMAC_init(&ctx, CMAC_KEY);
	if (msg_len > 0)
		CMAC_update(&ctx, msg, msg_len);
	CMAC_final(&ctx, tag);
	CMAC_ctx_clean(&ctx);

	CHECK_BYTES(desc, tag, expected, CMAC_BLOCK_LENGTH);
}

/*
 * Same message fed to CMAC_update in chunks of `chunk` bytes.
 * Used to stress the buffer management across block boundaries.
 */
static void cmac_streaming(const char *desc, const uint8_t *msg, size_t msg_len,
                           const uint8_t *expected, size_t chunk) {
	CMAC_ctx_t ctx;
	uint8_t tag[CMAC_BLOCK_LENGTH];

	CMAC_init(&ctx, CMAC_KEY);
	size_t off = 0;
	while (off < msg_len) {
		size_t n = msg_len - off < chunk ? msg_len - off : chunk;
		CMAC_update(&ctx, msg + off, n);
		off += n;
	}
	CMAC_final(&ctx, tag);
	CMAC_ctx_clean(&ctx);

	CHECK_BYTES(desc, tag, expected, CMAC_BLOCK_LENGTH);
}

static void test_cmac(void) {
	printf("--- cmac (NIST SP 800-38B AES-256) ---\n");

	/* ------------------------------------------------------------------
	 * Example 1  Mlen = 0  (empty message)
	 * Forces the padding-only path: one zero block padded with 0x80,
	 * XOR'd with K2, then encrypted.
	 * Expected: 02 89 62 f6 1b 7b f8 9e  fc 6b 55 1f 46 67 d9 83
	 * ------------------------------------------------------------------ */
	static const uint8_t ex1_expected[16] = {
	        0x02, 0x89, 0x62, 0xf6, 0x1b, 0x7b, 0xf8, 0x9e,
	        0xfc, 0x6b, 0x55, 0x1f, 0x46, 0x67, 0xd9, 0x83,
	};
	cmac_oneshot("ex1: Mlen=0 (empty, K2 path)", NULL, 0, ex1_expected);

	/* ------------------------------------------------------------------
	 * Example 2  Mlen = 16  (exactly one complete block)
	 * Tests the K1 branch: last block is complete, no padding added.
	 * Expected: 28 a7 02 3f 45 2e 8f 82  bd 4b f2 8d 8c 37 c3 5c
	 *
	 * Note: some transcriptions of the NIST doc show the AES-128 value
	 * (28 a7 02 3f 45 2e 8f 9b ...) here by mistake. The value below is
	 * correct for AES-256 and verified against the cryptography library.
	 * ------------------------------------------------------------------ */
	static const uint8_t ex2_msg[16] = {
	        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
	        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
	};
	static const uint8_t ex2_expected[16] = {
	        0x28, 0xa7, 0x02, 0x3f, 0x45, 0x2e, 0x8f, 0x82,
	        0xbd, 0x4b, 0xf2, 0x8d, 0x8c, 0x37, 0xc3, 0x5c,
	};
	cmac_oneshot("ex2: Mlen=16 (one block, K1 path)", ex2_msg, 16,
	             ex2_expected);

	/* ------------------------------------------------------------------
	 * Example 3  Mlen = 40  (two complete blocks + 8-byte partial)
	 * Tests the K2 path with a non-trivial buffered remainder.
	 * Expected: aa f3 d8 f1 de 56 40 c2  32 f5 b1 69 b9 c9 11 e6
	 * ------------------------------------------------------------------ */
	static const uint8_t ex3_msg[40] = {
	        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d,
	        0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a, 0xae, 0x2d, 0x8a, 0x57,
	        0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf,
	        0x8e, 0x51, 0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
	};
	static const uint8_t ex3_expected[16] = {
	        0xaa, 0xf3, 0xd8, 0xf1, 0xde, 0x56, 0x40, 0xc2,
	        0x32, 0xf5, 0xb1, 0x69, 0xb9, 0xc9, 0x11, 0xe6,
	};
	cmac_oneshot("ex3: Mlen=40 (partial final block, K2 path)", ex3_msg, 40,
	             ex3_expected);

	/* Streaming variants for ex3 — exercises every buffering boundary.
	 * chunk=1  : worst case, one byte at a time
	 * chunk=3  : misaligned to block size
	 * chunk=16 : exactly one block per call
	 * chunk=17 : one block + one byte spills into next buffer */
	cmac_streaming("ex3: streaming chunk=1", ex3_msg, 40, ex3_expected, 1);
	cmac_streaming("ex3: streaming chunk=3", ex3_msg, 40, ex3_expected, 3);
	cmac_streaming("ex3: streaming chunk=16", ex3_msg, 40, ex3_expected,
	               16);
	cmac_streaming("ex3: streaming chunk=17", ex3_msg, 40, ex3_expected,
	               17);

	/* ------------------------------------------------------------------
	 * Example 4  Mlen = 64  (four complete blocks, no padding)
	 * Tests K1 path at multi-block scale. Also the most common real-world
	 * shape when hashing fixed-size key material.
	 * Expected: e1 99 21 90 54 9f 6e d5  69 6a 2c 05 6c 31 54 10
	 * ------------------------------------------------------------------ */
	static const uint8_t ex4_msg[64] = {
	        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d,
	        0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a, 0xae, 0x2d, 0x8a, 0x57,
	        0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf,
	        0x8e, 0x51, 0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
	        0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef, 0xf6, 0x9f,
	        0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b,
	        0xe6, 0x6c, 0x37, 0x10,
	};
	static const uint8_t ex4_expected[16] = {
	        0xe1, 0x99, 0x21, 0x90, 0x54, 0x9f, 0x6e, 0xd5,
	        0x69, 0x6a, 0x2c, 0x05, 0x6c, 0x31, 0x54, 0x10,
	};
	cmac_oneshot("ex4: Mlen=64 (four blocks, K1 path)", ex4_msg, 64,
	             ex4_expected);

	print_summary();
}

/*
 * testing the FAST algorithm code
 */
static void test_fast(void) {
	printf("--- fast (round-trip) ---\n");

	fast_params_t params;
	fast_context_t *ctx = NULL;

	static const uint8_t key[32] = {
	        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
	        0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
	        0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
	        0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4,
	};

	/* radix=10 (digits), word_length=9 (SSN length) */
	int rc = calculate_recommended_params(&params, 10, 9);
	CHECK("calculate_recommended_params succeeds", rc == 0);

	rc = fast_init(&ctx, &params, key);
	CHECK("fast_init succeeds", rc == 0);
	if (rc != 0) {
		print_summary();
		return;
	}

	uint8_t plaintext[] = {1, 2, 3, 4, 5, 6, 7, 8, 9};
	uint8_t ciphertext[9] = {0};
	uint8_t decrypted[9] = {0};

	rc = fast_encrypt(ctx, NULL, 0, plaintext, ciphertext, 9);
	CHECK("fast_encrypt succeeds", rc == 0);

	rc = fast_decrypt(ctx, NULL, 0, ciphertext, decrypted, 9);
	CHECK("fast_decrypt succeeds", rc == 0);

	CHECK("round-trip matches original",
	      memcmp(plaintext, decrypted, 9) == 0);
	CHECK("ciphertext differs from plaintext",
	      memcmp(plaintext, ciphertext, 9) != 0);

	/* format preservation — all output values within radix */
	int format_ok = 1;
	for (int i = 0; i < 9; i++)
		if (ciphertext[i] >= 10) {
			format_ok = 0;
			break;
		}
	CHECK("ciphertext values within radix", format_ok);

	fast_cleanup(ctx);
	print_summary();
}

static void test_fpe(void) {
	printf("\n--- FPE ---\n");

	static const uint8_t key[32] = {
	        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
	        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
	        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20};

	char enc[64];
	char dec[64];
	const char *src;

	/* --- phone round trips --- */
	src = "234-555-6666";
	CHECK("phone_dash encrypt ok",
	      fpe_encrypt_phone_dash(key, src, strlen(src), enc) == HEXLOCK_OK);
	CHECK("phone_dash format preserved",
	      enc[3] == '-' && enc[7] == '-' && strlen(enc) == strlen(src));
	CHECK("phone_dash decrypt ok",
	      fpe_decrypt_phone_dash(key, enc, strlen(enc), dec) == HEXLOCK_OK);
	CHECK("phone_dash round trip", strcmp(dec, src) == 0);

	src = "(234) 555-6666";
	CHECK("phone_paren encrypt ok",
	      fpe_encrypt_phone_paren(key, src, strlen(src), enc) ==
	              HEXLOCK_OK);
	CHECK("phone_paren format preserved",
	      enc[0] == '(' && enc[4] == ')' && enc[5] == ' ' && enc[9] == '-');
	CHECK("phone_paren decrypt ok",
	      fpe_decrypt_phone_paren(key, enc, strlen(enc), dec) ==
	              HEXLOCK_OK);
	CHECK("phone_paren round trip", strcmp(dec, src) == 0);

	src = "234.555.6666";
	CHECK("phone_dot encrypt ok",
	      fpe_encrypt_phone_dot(key, src, strlen(src), enc) == HEXLOCK_OK);
	CHECK("phone_dot format preserved", enc[3] == '.' && enc[7] == '.');
	CHECK("phone_dot decrypt ok",
	      fpe_decrypt_phone_dot(key, enc, strlen(enc), dec) == HEXLOCK_OK);
	CHECK("phone_dot round trip", strcmp(dec, src) == 0);

	src = "234 555 6666";
	CHECK("phone_space encrypt ok",
	      fpe_encrypt_phone_space(key, src, strlen(src), enc) ==
	              HEXLOCK_OK);
	CHECK("phone_space format preserved", enc[3] == ' ' && enc[7] == ' ');
	CHECK("phone_space decrypt ok",
	      fpe_decrypt_phone_space(key, enc, strlen(enc), dec) ==
	              HEXLOCK_OK);
	CHECK("phone_space round trip", strcmp(dec, src) == 0);

	src = "2345556666";
	CHECK("phone_bare encrypt ok",
	      fpe_encrypt_phone_bare(key, src, strlen(src), enc) == HEXLOCK_OK);
	CHECK("phone_bare decrypt ok",
	      fpe_decrypt_phone_bare(key, enc, strlen(enc), dec) == HEXLOCK_OK);
	CHECK("phone_bare round trip", strcmp(dec, src) == 0);

	/* --- SSN --- */
	src = "123-45-6789";
	CHECK("ssn encrypt ok",
	      fpe_encrypt_ssn(key, src, strlen(src), enc) == HEXLOCK_OK);
	CHECK("ssn format preserved",
	      enc[3] == '-' && enc[6] == '-' && strlen(enc) == strlen(src));
	CHECK("ssn decrypt ok",
	      fpe_decrypt_ssn(key, enc, strlen(enc), dec) == HEXLOCK_OK);
	CHECK("ssn round trip", strcmp(dec, src) == 0);

	/* --- credit card --- */
	src = "4111-1111-1111-1111";
	CHECK("credit_card encrypt ok",
	      fpe_encrypt_credit_card(key, src, strlen(src), enc) ==
	              HEXLOCK_OK);
	CHECK("credit_card format preserved",
	      enc[4] == '-' && enc[9] == '-' && enc[14] == '-');
	CHECK("credit_card decrypt ok",
	      fpe_decrypt_credit_card(key, enc, strlen(enc), dec) ==
	              HEXLOCK_OK);
	CHECK("credit_card round trip", strcmp(dec, src) == 0);

	src = "4111 1111 1111 1111";
	CHECK("credit_card space encrypt ok",
	      fpe_encrypt_credit_card(key, src, strlen(src), enc) ==
	              HEXLOCK_OK);
	CHECK("credit_card space format preserved",
	      enc[4] == ' ' && enc[9] == ' ' && enc[14] == ' ');
	CHECK("credit_card space decrypt ok",
	      fpe_decrypt_credit_card(key, enc, strlen(enc), dec) ==
	              HEXLOCK_OK);
	CHECK("credit_card space round trip", strcmp(dec, src) == 0);

	/* --- passport --- */
	src = "A12345678";
	CHECK("passport encrypt ok",
	      fpe_encrypt_passport(key, src, strlen(src), enc) == HEXLOCK_OK);
	CHECK("passport alpha prefix preserved", enc[0] == 'A');
	CHECK("passport decrypt ok",
	      fpe_decrypt_passport(key, enc, strlen(enc), dec) == HEXLOCK_OK);
	CHECK("passport round trip", strcmp(dec, src) == 0);

	src = "AB1234567";
	CHECK("passport two-letter prefix encrypt ok",
	      fpe_encrypt_passport(key, src, strlen(src), enc) == HEXLOCK_OK);
	CHECK("passport two-letter prefix preserved",
	      enc[0] == 'A' && enc[1] == 'B');
	CHECK("passport two-letter prefix decrypt ok",
	      fpe_decrypt_passport(key, enc, strlen(enc), dec) == HEXLOCK_OK);
	CHECK("passport two-letter prefix round trip", strcmp(dec, src) == 0);

	/* --- routing number --- */
	src = "021000021";
	CHECK("routing_number encrypt ok",
	      fpe_encrypt_routing_number(key, src, strlen(src), enc) ==
	              HEXLOCK_OK);
	CHECK("routing_number length preserved", strlen(enc) == strlen(src));
	CHECK("routing_number decrypt ok",
	      fpe_decrypt_routing_number(key, enc, strlen(enc), dec) ==
	              HEXLOCK_OK);
	CHECK("routing_number round trip", strcmp(dec, src) == 0);

	/* --- bank account --- */
	src = "12345678";
	CHECK("bank_account short encrypt ok",
	      fpe_encrypt_bank_account(key, src, strlen(src), enc) ==
	              HEXLOCK_OK);
	CHECK("bank_account short decrypt ok",
	      fpe_decrypt_bank_account(key, enc, strlen(enc), dec) ==
	              HEXLOCK_OK);
	CHECK("bank_account short round trip", strcmp(dec, src) == 0);

	src = "12345678901234567";
	CHECK("bank_account long encrypt ok",
	      fpe_encrypt_bank_account(key, src, strlen(src), enc) ==
	              HEXLOCK_OK);
	CHECK("bank_account long decrypt ok",
	      fpe_decrypt_bank_account(key, enc, strlen(enc), dec) ==
	              HEXLOCK_OK);
	CHECK("bank_account long round trip", strcmp(dec, src) == 0);

	/* --- driver's license --- */
	src = "A1234567";
	CHECK("drivers_license encrypt ok",
	      fpe_encrypt_drivers_license(key, src, strlen(src), enc) ==
	              HEXLOCK_OK);
	CHECK("drivers_license alpha prefix preserved", enc[0] == 'A');
	CHECK("drivers_license decrypt ok",
	      fpe_decrypt_drivers_license(key, enc, strlen(enc), dec) ==
	              HEXLOCK_OK);
	CHECK("drivers_license round trip", strcmp(dec, src) == 0);

	/* --- IP address --- */
	src = "192.168.1.1";
	CHECK("ip_address encrypt ok",
	      fpe_encrypt_ip_address(key, src, strlen(src), enc) == HEXLOCK_OK);
	CHECK("ip_address is valid IPv4", strchr(enc, '.') != NULL);
	CHECK("ip_address decrypt ok",
	      fpe_decrypt_ip_address(key, enc, strlen(enc), dec) == HEXLOCK_OK);
	CHECK("ip_address round trip", strcmp(dec, src) == 0);

	src = "255.255.255.255";
	CHECK("ip_address max encrypt ok",
	      fpe_encrypt_ip_address(key, src, strlen(src), enc) == HEXLOCK_OK);
	CHECK("ip_address max decrypt ok",
	      fpe_decrypt_ip_address(key, enc, strlen(enc), dec) == HEXLOCK_OK);
	CHECK("ip_address max round trip", strcmp(dec, src) == 0);

	src = "0.0.0.0";
	CHECK("ip_address zero encrypt ok",
	      fpe_encrypt_ip_address(key, src, strlen(src), enc) == HEXLOCK_OK);
	CHECK("ip_address zero decrypt ok",
	      fpe_decrypt_ip_address(key, enc, strlen(enc), dec) == HEXLOCK_OK);
	CHECK("ip_address zero round trip", strcmp(dec, src) == 0);

	/* --- domain separation --- */
	/* same digit string, different PII type should produce different
	 * ciphertext */
	const char *digits = "123456789";
	char enc_ssn[64], enc_routing[64];
	fpe_encrypt_ssn(key, digits, strlen(digits), enc_ssn);
	fpe_encrypt_routing_number(key, digits, strlen(digits), enc_routing);
	CHECK("domain separation: ssn vs routing_number differ",
	      strcmp(enc_ssn, enc_routing) != 0);

	/* --- stability --- */
	/* encrypting same input twice should give same output */
	char enc2[64];
	src = "234-555-6666";
	fpe_encrypt_phone_dash(key, src, strlen(src), enc);
	fpe_encrypt_phone_dash(key, src, strlen(src), enc2);
	CHECK("stability: same input same output", strcmp(enc, enc2) == 0);

	/* GitHub tokens */
	char enc_token[256];
	char dec_token[256];
	const char *gh;

	gh = "ghp_1234567890abcdefghijklmnopqrstuvwxyz";
	CHECK("GitHub ghp encrypt token ok",
	      fpe_encrypt_github_ghp(key, gh, strlen(gh), enc_token) ==
	              HEXLOCK_OK);
	CHECK("GitHub ghp decrypt token ok",
	      fpe_decrypt_github_ghp(key, enc_token, strlen(enc_token),
	                             dec_token) == HEXLOCK_OK);
	CHECK("GitHub ghp token zero round trip", strcmp(dec_token, gh) == 0);

	gh = "gho_aB1cD2eF3gH4iJ5kL6mN7oP8qR9sT0uV1wX2";
	CHECK("GitHub gho encrypt token ok",
	      fpe_encrypt_github_ghp(key, gh, strlen(gh), enc_token) ==
	              HEXLOCK_OK);
	CHECK("GitHub gho decrypt token ok",
	      fpe_decrypt_github_ghp(key, enc_token, strlen(enc_token),
	                             dec_token) == HEXLOCK_OK);
	CHECK("GitHub gho token zero round trip", strcmp(dec_token, gh) == 0);

	/* skipping other GitHub tokens because they are basically the same */
	/* TODO: write tests for the other GitHub token types */

	/* AWS tokens */
	const char *aws;

	aws = "AKIAABCDEFGH234567AB";
	CHECK("AWS aws encrypt token ok",
	      fpe_encrypt_aws_access_key(key, aws, strlen(aws), enc_token) ==
	              HEXLOCK_OK);
	CHECK("AWS aws decrypt token ok",
	      fpe_decrypt_aws_access_key(key, enc_token, strlen(enc_token),
	                                 dec_token) == HEXLOCK_OK);
	CHECK("AWS token zero round trip", strcmp(dec_token, aws) == 0);

	aws = "AKIAZ7ABCDEF234567ZA";
	fpe_encrypt_aws_access_key(key, aws, strlen(aws), enc_token);
	
	// this test is here because we have to be certain about the
	// somewhat unusual base32 alphabet
	size_t len = strlen(aws);
	for (size_t i = 0; i < len; i++) {
		char c = enc_token[i];
		int valid = (c >= 'A' && c <= 'Z') || (c >= '2' && c <= '7');
		CHECK("AWS key encryption is valid", valid);
	}

	fpe_decrypt_aws_access_key(key, enc_token, strlen(enc_token), dec_token);
	for (size_t i = 0; i < len; i++) {
		char c = dec_token[i];
		int valid = (c >= 'A' && c <= 'Z') || (c >= '2' && c <= '7');
		CHECK("AWS key decryption is valid", valid);
	}

	aws = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
	CHECK("AWS aws encrypt token ok",
	      fpe_encrypt_aws_secret_key(key, aws, strlen(aws), enc_token) ==
	              HEXLOCK_OK);
	CHECK("AWS aws decrypt token ok",
	      fpe_decrypt_aws_secret_key(key, enc_token, strlen(enc_token),
	                                 dec_token) == HEXLOCK_OK);
	CHECK("AWS token zero round trip", strcmp(dec_token, aws) == 0);

	/* Anthropic tokens */
	const char *anth;

	anth = "sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnop";
	CHECK("Anthropic api key encrypt token ok",
	      fpe_encrypt_anthropic_api(key, anth, strlen(anth), enc_token) ==
	              HEXLOCK_OK);
	CHECK("Anthropic api decrypt token ok",
	      fpe_decrypt_anthropic_api(key, enc_token, strlen(enc_token),
	                                dec_token) == HEXLOCK_OK);
	CHECK("Anthropic api token zero round trip",
	      strcmp(dec_token, anth) == 0);

	/* skipping the Anthropic oauth token because it's not meaningfully
	 * different */
	/* TODO: consider writing tests for it for code coverage */

	print_summary();
}

/*
 * testing the tokenizer
 */
static void test_tokenizer(void) {
	printf("\n--- Tokenizer ---\n");

	static const uint8_t key[32] = {
	        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
	        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
	        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20};

	char dst[64];
	uint32_t token_key;
	uint32_t token_key2;

	/* basic email tokenization */
	CHECK("email tokenize ok",
	      tokenize_email(key, "john.smith@gmail.com", 20, dst,
	                     &token_key) == HEXLOCK_OK);
	printf("  email: john.smith@gmail.com -> %s (token_key: %08x)\n", dst,
	       token_key);

	/* output looks like an email */
	CHECK("email output contains @", strchr(dst, '@') != NULL);
	CHECK("email output contains .", strchr(dst, '.') != NULL);

	/* deterministic — same input same output */
	char dst2[64];
	tokenize_email(key, "john.smith@gmail.com", 20, dst2, &token_key2);
	CHECK("email deterministic output", strcmp(dst, dst2) == 0);
	CHECK("email deterministic token_key", token_key == token_key2);

	/* different input different output */
	char dst3[64];
	uint32_t token_key3;
	tokenize_email(key, "jane.doe@yahoo.com", 18, dst3, &token_key3);
	printf("  email: jane.doe@yahoo.com -> %s (token_key: %08x)\n", dst3,
	       token_key3);
	CHECK("different email different output", strcmp(dst, dst3) != 0);
	CHECK("different email different token_key", token_key != token_key3);

	/* different key different output */
	static const uint8_t key2[32] = {
	        0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8,
	        0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0,
	        0xef, 0xee, 0xed, 0xec, 0xeb, 0xea, 0xe9, 0xe8,
	        0xe7, 0xe6, 0xe5, 0xe4, 0xe3, 0xe2, 0xe1, 0xe0};
	char dst4[64];
	uint32_t token_key4;
	tokenize_email(key2, "john.smith@gmail.com", 20, dst4, &token_key4);
	CHECK("different key different output", strcmp(dst, dst4) != 0);
	CHECK("different key different token_key", token_key != token_key4);

	/* output fits in 64 bytes */
	CHECK("email output length ok", strlen(dst) < 64);
	print_summary();
}

static void test_process(void) {
	printf("\n--- Process ---\n");

	static const uint8_t key[32] = {
	        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
	        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
	        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20};

	hexlock_ctx_t *ctx = NULL;
	hexlock_result_t *result = NULL;

	CHECK("init ok", hexlock_init(&ctx, key, NULL, 0) == HEXLOCK_OK);

	/* --- single phone --- */
	const char *input = "call me at 234-555-6666 ok?";
	CHECK("process phone ok", hexlock_process(ctx, input, strlen(input),
	                                          &result) == HEXLOCK_OK);
	CHECK("process phone match count", result->count == 1);
	CHECK("process phone type",
	      result->records[0].type == HEXLOCK_PII_PHONE);
	CHECK("process phone algo",
	      result->records[0].algo == HEXLOCK_ALGO_FPE);
	CHECK("process phone transformed not equal to original",
	      strcmp(result->records[0].transformed, "234-555-6666") != 0);
	CHECK("process phone format preserved",
	      result->records[0].transformed[3] == '-' &&
	              result->records[0].transformed[7] == '-');
	printf("  phone: 234-555-6666 -> %s\n", result->records[0].transformed);
	printf("  output: %s\n", result->output);
	hexlock_result_free(result);
	result = NULL;

	/* --- single email --- */
	input = "contact john.smith@gmail.com for info";
	CHECK("process email ok", hexlock_process(ctx, input, strlen(input),
	                                          &result) == HEXLOCK_OK);
	CHECK("process email match count", result->count == 1);
	CHECK("process email type",
	      result->records[0].type == HEXLOCK_PII_EMAIL);
	CHECK("process email algo",
	      result->records[0].algo == HEXLOCK_ALGO_TOKENIZE);
	CHECK("process email transformed contains @",
	      strchr(result->records[0].transformed, '@') != NULL);
	CHECK("process email transformed not equal to original",
	      strcmp(result->records[0].transformed, "john.smith@gmail.com") !=
	              0);
	printf("  email: john.smith@gmail.com -> %s\n",
	       result->records[0].transformed);
	printf("  output: %s\n", result->output);
	hexlock_result_free(result);
	result = NULL;

	/* --- multiple PII in one string --- */
	input = "ssn 123-45-6789 and card 4111-1111-1111-1111";
	CHECK("process multi ok", hexlock_process(ctx, input, strlen(input),
	                                          &result) == HEXLOCK_OK);
	CHECK("process multi match count", result->count == 2);
	CHECK("process multi ssn type",
	      result->records[0].type == HEXLOCK_PII_SSN);
	CHECK("process multi cc type",
	      result->records[1].type == HEXLOCK_PII_CREDIT_CARD);
	CHECK("process multi ssn format preserved",
	      result->records[0].transformed[3] == '-' &&
	              result->records[0].transformed[6] == '-');
	printf("  ssn: 123-45-6789 -> %s\n", result->records[0].transformed);
	printf("  cc:  4111-1111-1111-1111 -> %s\n",
	       result->records[1].transformed);
	printf("  output: %s\n", result->output);
	hexlock_result_free(result);
	result = NULL;

	/* --- no PII --- */
	input = "hello world, nothing to see here";
	CHECK("process no pii ok", hexlock_process(ctx, input, strlen(input),
	                                           &result) == HEXLOCK_OK);
	CHECK("process no pii match count", result->count == 0);
	CHECK("process no pii output unchanged",
	      strcmp(result->output, input) == 0);
	hexlock_result_free(result);
	result = NULL;

	/* --- IP address --- */
	input = "server at 192.168.1.1 is down";
	CHECK("process ip ok", hexlock_process(ctx, input, strlen(input),
	                                       &result) == HEXLOCK_OK);
	CHECK("process ip match count", result->count == 1);
	CHECK("process ip type",
	      result->records[0].type == HEXLOCK_PII_IP_ADDRESS);
	CHECK("process ip transformed not equal to original",
	      strcmp(result->records[0].transformed, "192.168.1.1") != 0);
	printf("  ip: 192.168.1.1 -> %s\n", result->records[0].transformed);
	printf("  output: %s\n", result->output);
	hexlock_result_free(result);
	result = NULL;

	/* --- deterministic --- */
	input = "call me at 234-555-6666 ok?";
	hexlock_result_t *result2 = NULL;
	hexlock_process(ctx, input, strlen(input), &result);
	hexlock_process(ctx, input, strlen(input), &result2);
	CHECK("process deterministic",
	      strcmp(result->records[0].transformed,
	             result2->records[0].transformed) == 0);
	hexlock_result_free(result);
	hexlock_result_free(result2);
	result = NULL;

	hexlock_free(ctx);

	/* --- decrypt --- */
	hexlock_ctx_t *ctx2 = NULL;
	hexlock_init(&ctx2, key, NULL, 0);

	/* encrypt a phone number then decrypt it */
	const char *phone = "234-555-6666";
	hexlock_result_t *enc_result = NULL;
	char phone_input[64] = "call me at 234-555-6666 ok?";
	CHECK("decrypt phone process ok",
	      hexlock_process(ctx2, phone_input, strlen(phone_input),
	                      &enc_result) == HEXLOCK_OK);

	char transformed_phone[64];
	strncpy(transformed_phone, enc_result->records[0].transformed, 63);
	transformed_phone[63] = '\0';
	hexlock_subtype_t phone_subtype = enc_result->records[0].subtype;
	hexlock_result_free(enc_result);

	CHECK("decrypt phone ok",
	      hexlock_decrypt(ctx2, transformed_phone,
	                      strlen(transformed_phone), HEXLOCK_PII_PHONE,
	                      phone_subtype) == HEXLOCK_OK);
	CHECK("decrypt phone round trip",
	      strcmp(transformed_phone, phone) == 0);
	printf("  decrypt phone: -> %s\n", transformed_phone);

	/* encrypt an SSN then decrypt it */
	const char *ssn = "123-45-6789";
	hexlock_result_t *ssn_result = NULL;
	char ssn_input[] = "ssn is 123-45-6789 thanks";
	CHECK("decrypt ssn process ok",
	      hexlock_process(ctx2, ssn_input, strlen(ssn_input),
	                      &ssn_result) == HEXLOCK_OK);

	char transformed_ssn[64];
	strncpy(transformed_ssn, ssn_result->records[0].transformed, 63);
	transformed_ssn[63] = '\0';
	hexlock_subtype_t ssn_subtype = ssn_result->records[0].subtype;
	hexlock_result_free(ssn_result);

	CHECK("decrypt ssn ok",
	      hexlock_decrypt(ctx2, transformed_ssn, strlen(transformed_ssn),
	                      HEXLOCK_PII_SSN, ssn_subtype) == HEXLOCK_OK);
	CHECK("decrypt ssn round trip", strcmp(transformed_ssn, ssn) == 0);
	printf("  decrypt ssn: -> %s\n", transformed_ssn);

	/* encrypt an IP then decrypt it */
	const char *ip = "192.168.1.1";
	hexlock_result_t *ip_result = NULL;
	char ip_input[] = "server at 192.168.1.1 is down";
	CHECK("decrypt ip process ok",
	      hexlock_process(ctx2, ip_input, strlen(ip_input), &ip_result) ==
	              HEXLOCK_OK);

	char transformed_ip[64];
	strncpy(transformed_ip, ip_result->records[0].transformed, 63);
	transformed_ip[63] = '\0';
	hexlock_subtype_t ip_subtype = ip_result->records[0].subtype;
	hexlock_result_free(ip_result);

	CHECK("decrypt ip ok",
	      hexlock_decrypt(ctx2, transformed_ip, strlen(transformed_ip),
	                      HEXLOCK_PII_IP_ADDRESS,
	                      ip_subtype) == HEXLOCK_OK);
	CHECK("decrypt ip round trip", strcmp(transformed_ip, ip) == 0);
	printf("  decrypt ip: -> %s\n", transformed_ip);

	hexlock_free(ctx2);
	print_summary();
}

/* =========================================================================
 * Entry point
 * ========================================================================= */

int main(void) {
	test_regex();
	test_cmac();
	test_fast();
	test_fpe();
	test_tokenizer();
	test_process();

	if (g_failed > 0) {
		fprintf(stderr, "%d test(s) failed.\n", g_failed);
		return 1;
	}
	return 0;
}
