#ifndef CMAC_H
#define CMAC_H

#include "aes.h"

#define CMAC_BLOCK_LENGTH 16  // 128 bits for AES
#define AES_256 32
#define R_b 0x87

/*
 * holds CMAC context
 */
typedef struct CMAC_ctx_t {
        struct AES_ctx aes_ctx;
        uint8_t K[AES_256];
        uint8_t K1[CMAC_BLOCK_LENGTH];
        uint8_t K2[CMAC_BLOCK_LENGTH];
	uint8_t buf[CMAC_BLOCK_LENGTH];
	uint8_t x[CMAC_BLOCK_LENGTH];
	size_t buf_len;
} CMAC_ctx_t;

/*
 * init context
 * create subkeys K1 K2
 * set up initial block
 */
void CMAC_init(CMAC_ctx_t* ctx, const uint8_t* key);

/*
 * processes blocks
 * can be called multiple times
 */
void CMAC_update(CMAC_ctx_t* ctx, const uint8_t* data, size_t data_len);

/*
 * applies padding if necesary
 * XORs with K1 or K2
 * performs final block encryption
 * outputs tag
 */
void CMAC_final(CMAC_ctx_t* ctx, uint8_t* tag);

/*
 * cleans up a ctx
 */
void CMAC_ctx_clean(CMAC_ctx_t* ctx);

#endif
