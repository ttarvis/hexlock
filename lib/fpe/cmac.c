#include <string.h>
#include <stdio.h>

#include "aes.h"
#include "cmac.h"

#define CMAC_BLOCK_LENGTH 16  // 128 bits for AES
#define AES_BLOCK_LENGTH 16
#define AES_256 32
#define R_b 0x87

/*
 * makes a key
 */
void make_key(uint8_t *in, uint8_t *key) {
	unsigned char c = in[0];
	unsigned char carry = in[0] >> 7;
	unsigned char cnext;

	// Shift block to left, including carry
	for (int i = 0; i < AES_BLOCK_LENGTH - 1; i++, c = cnext) {
		key[i] = (c << 1) | ((cnext = in[i + 1]) >> 7);
	}

	// if carry is 0, it just shifts LS byte, otherwise XORs it
	// since 0 - carry will be either 0 or all bits = 1
	key[AES_BLOCK_LENGTH - 1] = (c << 1) ^ ((0 - carry) & 0X87);
}

/*
 * init context
 * create subkeys K1 K2
 * set up initial block
 */
void CMAC_init(CMAC_ctx_t *ctx, const uint8_t *key) {
	uint8_t L[CMAC_BLOCK_LENGTH] = {0};

	// zero it out first
	memset(ctx, 0, sizeof(CMAC_ctx_t));

	AES_init_ctx(&ctx->aes_ctx, key);

	// generate L
	AES_ECB_encrypt(&ctx->aes_ctx, L);

	// generate K1
	make_key(L, ctx->K1);

	// generate K2
	make_key(ctx->K1, ctx->K2);
}

/*
 * processes blocks
 * can be called multiple times
 */
void CMAC_update(CMAC_ctx_t *ctx, const uint8_t *data, size_t data_len) {
	if (!ctx || !data || data_len == 0) {
		return;
	}

	size_t offset = 0;

	// deal with partial buffer in the context
	if (ctx->buf_len > 0) {
		size_t needed = 16 - ctx->buf_len;
		size_t to_copy = data_len < needed ? data_len : needed;
		memcpy(ctx->buf + ctx->buf_len, data, to_copy);
		ctx->buf_len += to_copy;
		offset += to_copy;

		// only process the buffered block if we have more data coming
		if (ctx->buf_len == 16 && offset < data_len) {
			// XOR with chaining state
			for (int i = 0; i < 16; i++)
				ctx->buf[i] ^= ctx->x[i];
			// ECB encrypt
			memcpy(ctx->x, ctx->buf, 16);
			AES_ECB_encrypt(&ctx->aes_ctx, ctx->x);
			ctx->buf_len = 0;
		}
	}

	// process full blocks from input, but stop before the last block
	while (data_len - offset > 16) {
		// XOR with state
		for (int i = 0; i < 16; i++)
			ctx->x[i] ^= data[offset + i];
		// AES ECB encrypt
		AES_ECB_encrypt(&ctx->aes_ctx, ctx->x);
		offset += 16;
	}

	// buffer the remaining bytes — could be 1 to 16 bytes
	if (offset < data_len) {
		size_t remaining = data_len - offset;
		memcpy(ctx->buf + ctx->buf_len, data + offset, remaining);
		ctx->buf_len += remaining;
	}
}

/*
 * applies padding if necesary
 * XORs with K1 or K2
 * performs final block encryption
 * outputs tag
 */
void CMAC_final(CMAC_ctx_t *ctx, uint8_t *tag) {
	if (!ctx || !tag) {
		return;
	}

	uint8_t block[AES_BLOCK_LENGTH];

	if (ctx->buf_len == AES_BLOCK_LENGTH) {
		// complete last block — XOR with K1
		for (int i = 0; i < AES_BLOCK_LENGTH; i++)
			block[i] = ctx->buf[i] ^ ctx->K1[i];
	} else {
		// incomplete last block — pad then XOR with K2
		memcpy(block, ctx->buf, ctx->buf_len);
		block[ctx->buf_len] = 0x80;
		memset(block + ctx->buf_len + 1, 0, AES_BLOCK_LENGTH - ctx->buf_len - 1);
		for (int i = 0; i < AES_BLOCK_LENGTH; i++)
			block[i] ^= ctx->K2[i];
	}

	// XOR with chaining state
	for (int i = 0; i < AES_BLOCK_LENGTH; i++) {
		block[i] ^= ctx->x[i];
	}

	// encrypt — result is the tag
	AES_ECB_encrypt(&ctx->aes_ctx, block);

	memcpy(tag, block, AES_BLOCK_LENGTH);

	// zero the block — it contains the tag
	memset(block, 0, AES_BLOCK_LENGTH);
}

/*
 * cleans up a ctx
 * TODO: consider memset_s or explicit_bzero
 * minor/low risk of key leakage
 */
void CMAC_ctx_clean(CMAC_ctx_t *ctx) {
	memset(ctx, 0, sizeof(CMAC_ctx_t));
}
