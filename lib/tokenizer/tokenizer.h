#ifndef HEXLOCK_TOKENIZER_H
#define HEXLOCK_TOKENIZER_H

#include "../include/hexlock.h"
#include <stddef.h>
#include <stdint.h>

/*
 * Tokenizer — deterministic plausible replacement for PII types
 * that cannot be format-preserving encrypted meaningfully.
 *
 * For v1 only email is handled here. Name and address require NER (v2+).
 *
 * token_key_out: receives the 32-bit token key derived as CMAC(key, original)
 *                truncated to 4 bytes. Stored in hexlock_token_record_t.token_key
 *                so Python can use it for reverse lookup.
 *
 * dst:           caller-provided buffer, must be at least 64 bytes.
 *                (matches transformed[64] in hexlock_token_record_t)
 *
 * Enterprise flag HEXLOCK_FLAG_PRESERVE_DOMAIN (defined in hexlock.h) will
 * control domain preservation in a future version.
 */

hexlock_err_t tokenize_email(const uint8_t *key, const char *src, size_t src_len,
                             char *dst, uint32_t *token_key_out);

#endif /* HEXLOCK_TOKENIZER_H */
