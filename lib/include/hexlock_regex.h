/*
 * Internal header. Not exposed to callers.
 * Used only by router.c and regex.c.
 */

#ifndef HEXLOCK_REGEX_H
#define HEXLOCK_REGEX_H

#include "hexlock.h"

#include <stddef.h>

/*
 * the offsets of a match in a string for a certain
 * PII regex pattern
 */
typedef struct {
	hexlock_pii_type_t type;
	hexlock_subtype_t subtype;
	size_t start; /* byte offset into input, inclusive */
	size_t end;   /* byte offset into input, exclusive */
} hexlock_match_t;

/*
 * holds compiled regex patterns
 * never exposed
 * initialized by hexlock_regex_init(), freed by hexlock_regex_free()
 */
typedef struct hexlock_regex_ctx hexlock_regex_ctx_t;

/*
 * compile all PII patterns into a single PCRE2 database
 */
hexlock_err_t hexlock_regex_init(hexlock_regex_ctx_t **ctx,
                                 const hexlock_route_t *routes);
/*
 * free the compiled pattern database and scratch space
 */
void hexlock_regex_free(hexlock_regex_ctx_t *ctx);

/*
 * scan input for all PII matches in left-to-right order
 * No overlapping matches
 * Caller frees matches with hexlock_matches_free()
 */
hexlock_err_t hexlock_regex_scan(hexlock_regex_ctx_t *ctx, const char *input,
                                 size_t length, hexlock_match_t **matches,
                                 size_t *match_count);

void hexlock_matches_free(hexlock_match_t *matches, size_t count);

#endif /* HEXLOCK_REGEX_H */
