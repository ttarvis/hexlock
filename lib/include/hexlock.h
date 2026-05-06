#ifndef HEXLOCK_H
#define HEXLOCK_H

#include <stddef.h>
#include <stdint.h>

/*
 * below are route flags
 * XXX not intended for use presently just
 * here as an example for possible future uses
 */
#define HEXLOCK_FLAG_NONE 0x00000000
#define HEXLOCK_FLAG_PRESERVE_PREFIX 0x00000001
#define HEXLOCK_FLAG_PRESERVE_DOMAIN 0x00000002
#define HEXLOCK_FLAG_DISABLED 0x00000004

/*
 * these are PII types
 */
typedef enum {
	HEXLOCK_PII_EMAIL,
	HEXLOCK_PII_PHONE,
	HEXLOCK_PII_SSN,
	HEXLOCK_PII_CREDIT_CARD,
	HEXLOCK_PII_NAME,
	HEXLOCK_PII_ADDRESS,
	HEXLOCK_PII_DATE_OF_BIRTH,
	HEXLOCK_PII_IP_ADDRESS,
	HEXLOCK_PII_PASSPORT,
	HEXLOCK_PII_ROUTING_NUMBER,
	HEXLOCK_PII_BANK_ACCOUNT,
	HEXLOCK_PII_DRIVERS_LICENSE,
	HEXLOCK_PII_GITHUB_TOKEN,
	HEXLOCK_PII_AWS_ACCESS_KEY,
	HEXLOCK_PII_AWS_SECRET_KEY,
	HEXLOCK_PII_ANTHROPIC_KEY,
	//HEXLOCK_PII_JWT,
	HEXLOCK_PII_COUNT
} hexlock_pii_type_t;

/*
 * these are subtypes of all the PII
 * it's used for decrypting back
 * you can't just use regex to match data
 * again or it might decrypt things that
 * were never encrypted. So we need to know
 * the subtype to get the correct decryption
 * function
 */
typedef enum {
	HEXLOCK_SUBTYPE_NONE = 0,
	HEXLOCK_SUBTYPE_PHONE_PAREN,
	HEXLOCK_SUBTYPE_PHONE_DASH,
	HEXLOCK_SUBTYPE_PHONE_DOT,
	HEXLOCK_SUBTYPE_PHONE_SPACE,
	HEXLOCK_SUBTYPE_PHONE_BARE,
	HEXLOCK_SUBTYPE_SSN,
	HEXLOCK_SUBTYPE_CREDIT_CARD,
	HEXLOCK_SUBTYPE_IP_ADDRESS,
	HEXLOCK_SUBTYPE_PASSPORT,
	HEXLOCK_SUBTYPE_ROUTING_NUMBER,
	HEXLOCK_SUBTYPE_BANK_ACCOUNT,
	HEXLOCK_SUBTYPE_DRIVERS_LICENSE,
	HEXLOCK_SUBTYPE_EMAIL,
	HEXLOCK_SUBTYPE_GITHUB_GHP,      // personal access token     ghp_
	HEXLOCK_SUBTYPE_GITHUB_GHO,      // oauth access token        gho_
	HEXLOCK_SUBTYPE_GITHUB_GHU,      // user-to-server token      ghu_
	HEXLOCK_SUBTYPE_GITHUB_GHS,      // server-to-server token    ghs_
	HEXLOCK_SUBTYPE_GITHUB_GHR,      // refresh token             ghr_
	HEXLOCK_SUBTYPE_AWS_ACCESS_KEY,  // AKIA
	HEXLOCK_SUBTYPE_AWS_SECRET_KEY,
	HEXLOCK_SUBTYPE_ANTHROPIC_API,   // sk-ant-api03- + 48 chars
	HEXLOCK_SUBTYPE_ANTHROPIC_OAT,   // sk-ant-oat01- + 48 chars
	//HEXLOCK_SUBTYPE_JWT,
} hexlock_subtype_t;

/*
 * enum containing the current transform algorithms
 * XXX there are probably more
 */
typedef enum { HEXLOCK_ALGO_FPE, HEXLOCK_ALGO_TOKENIZE } hexlock_algorithm_t;

/*
 * describes how the router should treat
 * data when a match is found
 * example if CC then use FPE
 * it is used in a map where keys are
 * the PII types above (an array).
 */
typedef struct {
	hexlock_pii_type_t type;
	hexlock_algorithm_t algo;
	uint32_t flags;
	void *options; /* reserved, always NULL */
} hexlock_route_t;

/*
 * used for each value that gets either
 * tokenized or encrypted.
 * One of these is saved in memory in an array
 * of these to keep track of what was tokenized/encrypted
 * so a reverse lookup can be made
 * Fixed size, no internal pointers, safe to copy across the C/Python boundary
 * token_key is only meaningful when algo == HEXLOCK_ALGO_TOKENIZE
 */
typedef struct {
	hexlock_pii_type_t type;
	hexlock_algorithm_t algo;
	hexlock_subtype_t subtype;
	uint32_t token_key;
	char transformed[256];
	char original[256];
} hexlock_token_record_t;

/*
 * used for holding the output after encryption
 * and tokenization
 */
typedef struct {
	char *output;                    /* reconstructed string */
	hexlock_token_record_t *records; /* flat array, length count */
	size_t count;
} hexlock_result_t;

/*
 * just error codes
 */
typedef enum {
	HEXLOCK_OK = 0,
	HEXLOCK_ERR_NOMEM = -1,
	HEXLOCK_ERR_REGEX = -2,
	HEXLOCK_ERR_INVALID_KEY = -3,
	HEXLOCK_ERR_INVALID_TYPE = -4,
	HEXLOCK_ERR_INTERNAL = -5
} hexlock_err_t;

typedef struct hexlock_ctx hexlock_ctx_t;

/*
 * Initialize a context. key must be exactly 32 bytes (256-bit)
 * key is copied into the context. Caller may zero their copy after init
 * routes may be NULL to use all defaults
 * route_count is the number of entries in routes
 * Only entries present in routes override defaults
 */
hexlock_err_t hexlock_init(hexlock_ctx_t **ctx, const uint8_t *key,
                           const hexlock_route_t *routes, size_t route_count);

void hexlock_free(hexlock_ctx_t *ctx);

/*
 * Scan input, transform all PII, return result.
 * Caller must free result with hexlock_result_free().
 */
hexlock_err_t hexlock_process(hexlock_ctx_t *ctx, const char *input,
                              size_t length, hexlock_result_t **result);

void hexlock_result_free(hexlock_result_t *result);

/*
 * Decrypt a single FPE-encrypted value in place
 * type is needed to select the correct FPE domain
 */
hexlock_err_t hexlock_decrypt(hexlock_ctx_t *ctx, char *buf, size_t length,
                              hexlock_pii_type_t type,
                              hexlock_subtype_t subtype);

#endif /* HEXLOCK_H */
