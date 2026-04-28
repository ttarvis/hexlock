#include "tokenizer.h"

#include "../fpe/cmac.h"
#include "../include/hexlock.h"
#include "wordlist.h"

#include <stdint.h>
#include <string.h>

#define WORDLIST_SIZE (sizeof(wordlist) / sizeof(wordlist[0]))

/*
 * TLD pool
 */
static const char *tlds[] = {".com", ".net", ".org", ".io"};
#define TLD_COUNT (sizeof(tlds) / sizeof(tlds[0]))

/*
 * Derive a 32-bit token key from CMAC(key, src)
 * CMAC produces 16 bytes — we take the first 4 as a big-endian uint32_t
 * Deterministic: same key + same src always gives same token key
 */
static uint32_t derive_token_key(const uint8_t *key, const char *src,
                                 size_t src_len) {
	CMAC_ctx_t ctx;
	uint8_t tag[16];

	CMAC_init(&ctx, key);
	CMAC_update(&ctx, (const uint8_t *)src, src_len);
	CMAC_final(&ctx, tag);
	CMAC_ctx_clean(&ctx);

	// big-endian truncation to 32 bits
	return ((uint32_t)tag[0] << 24) | ((uint32_t)tag[1] << 16) |
	       ((uint32_t)tag[2] << 8) | ((uint32_t)tag[3]);
}

/*
 * Write a word from the wordlist into dst, starting at offset pos
 * returns the number of characters written, or -1 if dst would overflow
 * dst_size is the total buffer size including null terminator
 */
static int write_word(char *dst, size_t dst_size, size_t pos,
                      const char *word) {
	size_t wlen = strlen(word);
	if (pos + wlen >= dst_size) {
		return -1;
	}
	memcpy(dst + pos, word, wlen);
	return (int)wlen;
}

/*
 * write a literal string into dst at offset pos
 * returns number of characters written, or -1 on overflow
 */
static int write_lit(char *dst, size_t dst_size, size_t pos, const char *lit) {
	return write_word(dst, dst_size, pos, lit);
}

/*
 * Generate a plausible fake email address deterministically from token_key
 * in the format: word1.word2@word3.tld
 * word1 = wordlist[token_key % WORDLIST_SIZE]
 * word2 = wordlist[(token_key >> 13) % WORDLIST_SIZE]
 * word3 = wordlist[(token_key >>  7) % WORDLIST_SIZE]
 * tld   = tlds[(token_key >> 2) % TLD_COUNT]
 * dst must be at least 64 bytes.
 * TODO: these numbers are picked kind of randomly, we can change them
 */
static hexlock_err_t generate_fake_email(uint32_t token_key, char *dst,
                                         size_t dst_size) {
	const char *word1 = wordlist[token_key % WORDLIST_SIZE];
	const char *word2 = wordlist[(token_key >> 13) % WORDLIST_SIZE];
	const char *word3 = wordlist[(token_key >> 7) % WORDLIST_SIZE];
	const char *tld = tlds[(token_key >> 2) % TLD_COUNT];

	size_t pos = 0;
	int n;

	if ((n = write_word(dst, dst_size, pos, word1)) < 0) {
		return HEXLOCK_ERR_INTERNAL;
	}
	pos += (size_t)n;

	if ((n = write_lit(dst, dst_size, pos, ".")) < 0) { 
		return HEXLOCK_ERR_INTERNAL;
	}
	pos += (size_t)n;

	if ((n = write_word(dst, dst_size, pos, word2)) < 0) {
		return HEXLOCK_ERR_INTERNAL;
	}
	pos += (size_t)n;

	if ((n = write_lit(dst, dst_size, pos, "@")) < 0) {
		return HEXLOCK_ERR_INTERNAL;
	}
	pos += (size_t)n;

	if ((n = write_word(dst, dst_size, pos, word3)) < 0) {
		return HEXLOCK_ERR_INTERNAL;
	}
	pos += (size_t)n;

	if ((n = write_lit(dst, dst_size, pos, tld)) < 0) {
		return HEXLOCK_ERR_INTERNAL;
	}
	pos += (size_t)n;

	dst[pos] = '\0';
	return HEXLOCK_OK;
}

/*
 * Tokenize an email address
 * Derives a 32-bit token key from CMAC(key, src), uses it to generate
 * a plausible fake email, writes it to dst, and returns the token key
 * in token_key_out for Python's reverse lookup table
 */
hexlock_err_t tokenize_email(const uint8_t *key, const char *src,
                             size_t src_len, char *dst,
                             uint32_t *token_key_out) {
	if (!key || !src || !dst || !token_key_out) {
		return HEXLOCK_ERR_INTERNAL;
	}
	if (src_len == 0) {
		return HEXLOCK_ERR_INTERNAL;
	}

	uint32_t token_key = derive_token_key(key, src, src_len);
	*token_key_out = token_key;

	return generate_fake_email(token_key, dst, 64);
}
