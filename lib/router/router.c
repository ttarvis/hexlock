#include "../fpe/fpe.h"
#include "../include/hexlock.h"
#include "../include/hexlock_regex.h"
#include "../tokenizer/tokenizer.h"

#include <stdlib.h>
#include <string.h>

/*
 * defines context
 * This is sensitive and immutable
 * It us used for each session on init
 */
struct hexlock_ctx {
	hexlock_route_t routes[HEXLOCK_PII_COUNT];
	uint8_t key[32];
	hexlock_regex_ctx_t *regex;
};

/*
 * setps up an array containing default values
 */
// clang-format off
static const hexlock_route_t default_routes[HEXLOCK_PII_COUNT] = {
        [HEXLOCK_PII_EMAIL] = {HEXLOCK_PII_EMAIL, HEXLOCK_ALGO_TOKENIZE, HEXLOCK_FLAG_NONE, NULL},
        [HEXLOCK_PII_PHONE] = {HEXLOCK_PII_PHONE, HEXLOCK_ALGO_FPE, HEXLOCK_FLAG_NONE, NULL},
        [HEXLOCK_PII_SSN] = {HEXLOCK_PII_SSN, HEXLOCK_ALGO_FPE, HEXLOCK_FLAG_NONE, NULL},
        [HEXLOCK_PII_CREDIT_CARD] = {HEXLOCK_PII_CREDIT_CARD, HEXLOCK_ALGO_FPE, HEXLOCK_FLAG_NONE, NULL},
        [HEXLOCK_PII_NAME] = {HEXLOCK_PII_NAME, HEXLOCK_ALGO_TOKENIZE, HEXLOCK_FLAG_NONE, NULL},
        [HEXLOCK_PII_ADDRESS] = {HEXLOCK_PII_ADDRESS, HEXLOCK_ALGO_TOKENIZE, HEXLOCK_FLAG_NONE, NULL},
        [HEXLOCK_PII_DATE_OF_BIRTH] = {HEXLOCK_PII_DATE_OF_BIRTH, HEXLOCK_ALGO_FPE, HEXLOCK_FLAG_NONE, NULL},
        [HEXLOCK_PII_IP_ADDRESS] = {HEXLOCK_PII_IP_ADDRESS, HEXLOCK_ALGO_FPE, HEXLOCK_FLAG_NONE, NULL},
	[HEXLOCK_PII_PASSPORT]        = {HEXLOCK_PII_PASSPORT,        HEXLOCK_ALGO_FPE, HEXLOCK_FLAG_NONE, NULL},
	[HEXLOCK_PII_ROUTING_NUMBER]  = {HEXLOCK_PII_ROUTING_NUMBER,  HEXLOCK_ALGO_FPE, HEXLOCK_FLAG_NONE, NULL},
	[HEXLOCK_PII_BANK_ACCOUNT]    = {HEXLOCK_PII_BANK_ACCOUNT,    HEXLOCK_ALGO_FPE, HEXLOCK_FLAG_NONE, NULL},
	[HEXLOCK_PII_DRIVERS_LICENSE] = {HEXLOCK_PII_DRIVERS_LICENSE, HEXLOCK_ALGO_FPE, HEXLOCK_FLAG_NONE, NULL},
	[HEXLOCK_PII_GITHUB_TOKEN]   = {HEXLOCK_PII_GITHUB_TOKEN,   HEXLOCK_ALGO_FPE, HEXLOCK_FLAG_NONE, NULL},
	[HEXLOCK_PII_AWS_ACCESS_KEY] = {HEXLOCK_PII_AWS_ACCESS_KEY, HEXLOCK_ALGO_FPE, HEXLOCK_FLAG_NONE, NULL},
	[HEXLOCK_PII_AWS_SECRET_KEY] = {HEXLOCK_PII_AWS_SECRET_KEY, HEXLOCK_ALGO_FPE, HEXLOCK_FLAG_NONE, NULL},
	[HEXLOCK_PII_ANTHROPIC_KEY]  = {HEXLOCK_PII_ANTHROPIC_KEY,  HEXLOCK_ALGO_FPE, HEXLOCK_FLAG_NONE, NULL},
	//[HEXLOCK_PII_JWT]            = {HEXLOCK_PII_JWT,            HEXLOCK_ALGO_FPE, HEXLOCK_FLAG_NONE, NULL},
};
// clang-format on

/*
 * starts a session
 */
hexlock_err_t hexlock_init(hexlock_ctx_t **ctx, const uint8_t *key,
                           const hexlock_route_t *routes, size_t route_count) {
	if (!ctx || !key) {
		return HEXLOCK_ERR_INVALID_KEY;
	}

	hexlock_ctx_t *c = calloc(1, sizeof(*c));
	if (!c) {
		return HEXLOCK_ERR_NOMEM;
	}

	// copy key
	memcpy(c->key, key, 32);

	// start with defaults
	memcpy(c->routes, default_routes, sizeof(default_routes));

	// merge caller overrides with defaults
	for (size_t i = 0; i < route_count; i++) {
		hexlock_pii_type_t t = routes[i].type;
		if (t >= HEXLOCK_PII_COUNT) {
			free(c);
			return HEXLOCK_ERR_INVALID_TYPE;
		}
		c->routes[t] = routes[i];  // looks up the type in the array of
		                           // routes and replaces it
	}

	// init regex
	hexlock_err_t err = hexlock_regex_init(&c->regex, c->routes);
	if (err != HEXLOCK_OK) {
		free(c);
		return err;
	}

	*ctx = c;
	return HEXLOCK_OK;
}

/*
 * just frees and zeroes out a context
 */
void hexlock_free(hexlock_ctx_t *ctx) {
	if (!ctx) {
		return;
	}
	hexlock_regex_free(ctx->regex);
	memset(ctx->key, 0, 32); /* zero key before free */
	free(ctx);
}

/*
 * frees a result struct, the thing we pass back to python
 */
void hexlock_result_free(hexlock_result_t *result) {
	if (!result) {
		return;
	}
	free(result->output);
	free(result->records);
	free(result);
}

/*
 * this type is used in dispatch as a type for the correct
 * encryption/tokenization function for a PII subtype
 */
typedef hexlock_err_t (*fpe_fn_t)(const uint8_t *, const char *, size_t,
                                  char *);

/*
 * matching encrypt and decrypt function pointers for
 * a particular PII subtype
 */
typedef struct {
	hexlock_subtype_t subtype;
	fpe_fn_t encrypt;
	fpe_fn_t decrypt;
} fpe_dispatch_t;

/*
 * These are all the subtypes and matching encryt/decrypt
 * functions. Must be updated if new subtypes added
 */
static const fpe_dispatch_t fpe_dispatch[] = {
        {HEXLOCK_SUBTYPE_PHONE_PAREN, fpe_encrypt_phone_paren,
         fpe_decrypt_phone_paren},
        {HEXLOCK_SUBTYPE_PHONE_DASH, fpe_encrypt_phone_dash,
         fpe_decrypt_phone_dash},
        {HEXLOCK_SUBTYPE_PHONE_DOT, fpe_encrypt_phone_dot,
         fpe_decrypt_phone_dot},
        {HEXLOCK_SUBTYPE_PHONE_SPACE, fpe_encrypt_phone_space,
         fpe_decrypt_phone_space},
        {HEXLOCK_SUBTYPE_PHONE_BARE, fpe_encrypt_phone_bare,
         fpe_decrypt_phone_bare},
        {HEXLOCK_SUBTYPE_SSN, fpe_encrypt_ssn, fpe_decrypt_ssn},
        {HEXLOCK_SUBTYPE_CREDIT_CARD, fpe_encrypt_credit_card,
         fpe_decrypt_credit_card},
        {HEXLOCK_SUBTYPE_IP_ADDRESS, fpe_encrypt_ip_address,
         fpe_decrypt_ip_address},
        {HEXLOCK_SUBTYPE_PASSPORT, fpe_encrypt_passport, fpe_decrypt_passport},
        {HEXLOCK_SUBTYPE_ROUTING_NUMBER, fpe_encrypt_routing_number,
         fpe_decrypt_routing_number},
        {HEXLOCK_SUBTYPE_BANK_ACCOUNT, fpe_encrypt_bank_account,
         fpe_decrypt_bank_account},
        {HEXLOCK_SUBTYPE_DRIVERS_LICENSE, fpe_encrypt_drivers_license,
         fpe_decrypt_drivers_license},
        {HEXLOCK_SUBTYPE_GITHUB_GHP, fpe_encrypt_github_ghp,
         fpe_decrypt_github_ghp},
        {HEXLOCK_SUBTYPE_GITHUB_GHO, fpe_encrypt_github_gho,
         fpe_decrypt_github_gho},
        {HEXLOCK_SUBTYPE_GITHUB_GHU, fpe_encrypt_github_ghu,
         fpe_decrypt_github_ghu},
        {HEXLOCK_SUBTYPE_GITHUB_GHS, fpe_encrypt_github_ghs,
         fpe_decrypt_github_ghs},
        {HEXLOCK_SUBTYPE_GITHUB_GHR, fpe_encrypt_github_ghr,
         fpe_decrypt_github_ghr},
        {HEXLOCK_SUBTYPE_AWS_ACCESS_KEY, fpe_encrypt_aws_access_key,
         fpe_decrypt_aws_access_key},
        {HEXLOCK_SUBTYPE_AWS_SECRET_KEY, fpe_encrypt_aws_secret_key,
         fpe_decrypt_aws_secret_key},
        {HEXLOCK_SUBTYPE_ANTHROPIC_API, fpe_encrypt_anthropic_api,
         fpe_decrypt_anthropic_api},
        {HEXLOCK_SUBTYPE_ANTHROPIC_OAT, fpe_encrypt_anthropic_oat,
         fpe_decrypt_anthropic_oat},
        //{HEXLOCK_SUBTYPE_JWT, fpe_encrypt_jwt, fpe_decrypt_jwt},
};

// TODO: consider moving this to the top
#define FPE_DISPATCH_COUNT (sizeof(fpe_dispatch) / sizeof(fpe_dispatch[0]))

/*
 * retrieves encrypt function
 */
static fpe_fn_t lookup_fpe_encrypt(hexlock_subtype_t subtype) {
	for (size_t i = 0; i < FPE_DISPATCH_COUNT; i++) {
		if (fpe_dispatch[i].subtype == subtype)
			return fpe_dispatch[i].encrypt;
	}
	return NULL;
}

/*
 * retrieves decrypt function
 */
static fpe_fn_t lookup_fpe_decrypt(hexlock_subtype_t subtype) {
	for (size_t i = 0; i < FPE_DISPATCH_COUNT; i++) {
		if (fpe_dispatch[i].subtype == subtype)
			return fpe_dispatch[i].decrypt;
	}
	return NULL;
}

/*
 * actually processes the data for PII and starts the process of
 * encrypting or tokenizing
 * starting point for the C boundary
 */
hexlock_err_t hexlock_process(hexlock_ctx_t *ctx, const char *input,
                              size_t length, hexlock_result_t **out) {
	if (!ctx || !input || !out) {
		return HEXLOCK_ERR_INTERNAL;
	}

	/* scan for matches */
	hexlock_match_t *matches = NULL;
	size_t match_count = 0;

	hexlock_err_t err = hexlock_regex_scan(ctx->regex, input, length,
	                                       &matches, &match_count);
	if (err != HEXLOCK_OK)
		return err;

	/* allocate result */
	hexlock_result_t *result = calloc(1, sizeof(*result));
	if (!result) {
		hexlock_matches_free(matches, match_count);
		return HEXLOCK_ERR_NOMEM;
	}

	/* allocate output buffer — oversized, trimmed later */
	result->output = malloc(length * 3 + 1);
	if (!result->output) {
		free(result);
		hexlock_matches_free(matches, match_count);
		return HEXLOCK_ERR_NOMEM;
	}

	/* allocate records array */
	if (match_count > 0) {
		result->records =
		        calloc(match_count, sizeof(hexlock_token_record_t));
		if (!result->records) {
			free(result->output);
			free(result);
			hexlock_matches_free(matches, match_count);
			return HEXLOCK_ERR_NOMEM;
		}
	}

	/*
	 * Reconstruct output string left to right.
	 * For each match: copy non-PII segment, apply transform, record result.
	 */
	size_t in_pos = 0;
	size_t out_pos = 0;

	for (size_t i = 0; i < match_count; i++) {
		hexlock_match_t *m = &matches[i];

		/* copy non-PII segment before this match */
		size_t seg_len = m->start - in_pos;
		memcpy(result->output + out_pos, input + in_pos, seg_len);
		out_pos += seg_len;

		/* record metadata */
		hexlock_route_t *route = &ctx->routes[m->type];
		result->records[i].type = m->type;
		result->records[i].algo = route->algo;

		size_t match_len = m->end - m->start;
		char transformed[64];

		if (route->algo == HEXLOCK_ALGO_FPE) {
			fpe_fn_t fn = lookup_fpe_encrypt(m->subtype);
			if (!fn) {
				hexlock_matches_free(matches, match_count);
				hexlock_result_free(result);
				return HEXLOCK_ERR_INTERNAL;
			}
			hexlock_err_t ferr = fn(ctx->key, input + m->start,
			                        match_len, transformed);
			if (ferr != HEXLOCK_OK) {
				hexlock_matches_free(matches, match_count);
				hexlock_result_free(result);
				return ferr;
			}
			strncpy(result->records[i].transformed, transformed,
			        63);
			result->records[i].transformed[63] = '\0';
			result->records[i].token_key = 0;
			result->records[i].subtype = m->subtype;
			result->records[i].original[0] = '\0';

		} else if (route->algo == HEXLOCK_ALGO_TOKENIZE) {
			uint32_t token_key = 0;
			hexlock_err_t terr = tokenize_email(
			        ctx->key, input + m->start, match_len,
			        transformed, &token_key);
			if (terr != HEXLOCK_OK) {
				hexlock_matches_free(matches, match_count);
				hexlock_result_free(result);
				return terr;
			}
			strncpy(result->records[i].transformed, transformed,
			        63);
			result->records[i].transformed[63] = '\0';
			result->records[i].token_key = token_key;
			size_t orig_len = match_len < 255 ? match_len : 255;
			memcpy(result->records[i].original, input + m->start,
			       orig_len);
			result->records[i].original[orig_len] = '\0';
		}

		/* write transformed value into output */
		size_t transformed_len = strlen(transformed);
		memcpy(result->output + out_pos, transformed, transformed_len);
		out_pos += transformed_len;
		in_pos = m->end;
	}

	/* copy trailing non-PII segment */
	size_t tail = length - in_pos;
	memcpy(result->output + out_pos, input + in_pos, tail);
	out_pos += tail;
	result->output[out_pos] = '\0';

	/* trim output buffer to actual size */
	char *trimmed = realloc(result->output, out_pos + 1);
	if (trimmed)
		result->output = trimmed;

	result->count = match_count;
	hexlock_matches_free(matches, match_count);

	*out = result;
	return HEXLOCK_OK;
}

/*
 * calls out to fpe to decrypt and reformat in various ways
 */
hexlock_err_t hexlock_decrypt(hexlock_ctx_t *ctx, char *buf, size_t length,
                              hexlock_pii_type_t type,
                              hexlock_subtype_t subtype) {
	if (!ctx || !buf) {
		return HEXLOCK_ERR_INTERNAL;
	}

	/* tokenized values are not decrypted in C — Python handles reverse
	 * lookup */
	hexlock_route_t *route = &ctx->routes[type];
	if (route->algo == HEXLOCK_ALGO_TOKENIZE) {
		return HEXLOCK_OK;
	}

	fpe_fn_t fn = lookup_fpe_decrypt(subtype);
	if (!fn) {
		return HEXLOCK_ERR_INTERNAL;
	}

	char out[64];
	hexlock_err_t err = fn(ctx->key, buf, length, out);
	if (err != HEXLOCK_OK) {
		return err;
	}

	memcpy(buf, out, length);
	buf[length] = '\0';
	return HEXLOCK_OK;
}
