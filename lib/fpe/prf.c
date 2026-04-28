#include "cmac.h"
#include "fast_internal.h"

#include <stdlib.h>
#include <string.h>

/*
 * prf_derive_key
 *
 * Counter-mode KDF using AES-256-CMAC as the PRF.
 * Generates output_len bytes by iterating:
 *
 *   output[i] = CMAC(master_key, counter || input)
 *
 * where counter is a big-endian uint32 starting at 0, incremented
 * each iteration. Output blocks are concatenated and truncated to
 * output_len bytes. This matches the structure of the original
 * OpenSSL implementation.
 */
int prf_derive_key(const uint8_t *master_key, const uint8_t *input,
                   size_t input_len, uint8_t *output, size_t output_len) {
	if (!master_key || !input || !output || output_len == 0)
		return -1;

	/* Allocate input buffer once: 4-byte counter + input */
	size_t total_input_len = 4 + input_len;
	uint8_t *cmac_input = malloc(total_input_len);
	if (!cmac_input)
		return -1;
	memcpy(cmac_input + 4, input, input_len);

	CMAC_ctx_t ctx;
	CMAC_init(&ctx, master_key);

	size_t bytes_generated = 0;
	uint32_t counter = 0;

	while (bytes_generated < output_len) {
		/* Prepend big-endian counter */
		cmac_input[0] = (counter >> 24) & 0xFF;
		cmac_input[1] = (counter >> 16) & 0xFF;
		cmac_input[2] = (counter >> 8) & 0xFF;
		cmac_input[3] = counter & 0xFF;

		uint8_t cmac_output[CMAC_BLOCK_LENGTH];
		CMAC_update(&ctx, cmac_input, total_input_len);
		CMAC_final(&ctx, cmac_output);

		size_t to_copy = output_len - bytes_generated;
		if (to_copy > CMAC_BLOCK_LENGTH)
			to_copy = CMAC_BLOCK_LENGTH;
		memcpy(output + bytes_generated, cmac_output, to_copy);

		bytes_generated += to_copy;
		counter++;
	}

	CMAC_ctx_clean(&ctx);
	memset(cmac_input, 0, total_input_len);
	free(cmac_input);
	return 0;
}
