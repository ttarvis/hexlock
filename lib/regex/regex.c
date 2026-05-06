#define PCRE2_CODE_UNIT_WIDTH 8
#include "../include/hexlock.h"
#include "../include/hexlock_patterns.h"
#include "../include/hexlock_regex.h"

#include <pcre2.h>
#include <stdlib.h>
#include <string.h>

/*
 *
 */
#define PATTERN_TABLE_COUNT (sizeof(pattern_table) / sizeof(pattern_table[0]))

/*
 * define regex context
 * it holds the expensive compiled
 * pattern database.
 * Also offset vector basically just writes
 * it into the match_data
 * then the total number of capture groups
 */
struct hexlock_regex_ctx {
	pcre2_code *pattern;
	pcre2_match_data *match_data;
	uint32_t capture_count;
	uint32_t name_count;       // number of named groups
	uint32_t name_entry_size;  // size of each name table entry
	PCRE2_UCHAR *name_table;   // pointer to name table
};

/*
 * Pattern table
 * Maps named capture groups to PII types.
 * Order determines alternation priority — more specific patterns first.
 * All phone variants map to HEXLOCK_PII_PHONE.
 */
typedef struct {
	const char *name; /* named group in the pattern */
	hexlock_pii_type_t type;
	hexlock_subtype_t subtype;
} hexlock_pattern_entry_t;

static const hexlock_pattern_entry_t pattern_table[] = {
        {"email", HEXLOCK_PII_EMAIL, HEXLOCK_SUBTYPE_EMAIL},
        {"ssn", HEXLOCK_PII_SSN, HEXLOCK_SUBTYPE_SSN},
        {"credit_card", HEXLOCK_PII_CREDIT_CARD, HEXLOCK_SUBTYPE_CREDIT_CARD},
        {"ip_address", HEXLOCK_PII_IP_ADDRESS, HEXLOCK_SUBTYPE_IP_ADDRESS},
        {"routing_number", HEXLOCK_PII_ROUTING_NUMBER,
         HEXLOCK_SUBTYPE_ROUTING_NUMBER},
        {"passport", HEXLOCK_PII_PASSPORT, HEXLOCK_SUBTYPE_PASSPORT},
        {"drivers_license", HEXLOCK_PII_DRIVERS_LICENSE,
         HEXLOCK_SUBTYPE_DRIVERS_LICENSE},
        {"bank_account", HEXLOCK_PII_BANK_ACCOUNT,
         HEXLOCK_SUBTYPE_BANK_ACCOUNT},
        {"phone_paren", HEXLOCK_PII_PHONE, HEXLOCK_SUBTYPE_PHONE_PAREN},
        {"phone_dash", HEXLOCK_PII_PHONE, HEXLOCK_SUBTYPE_PHONE_DASH},
        {"phone_dot", HEXLOCK_PII_PHONE, HEXLOCK_SUBTYPE_PHONE_DOT},
        {"phone_space", HEXLOCK_PII_PHONE, HEXLOCK_SUBTYPE_PHONE_SPACE},
        {"phone_bare", HEXLOCK_PII_PHONE, HEXLOCK_SUBTYPE_PHONE_BARE},
        {"github_ghp", HEXLOCK_PII_GITHUB_TOKEN, HEXLOCK_SUBTYPE_GITHUB_GHP},
        {"github_gho", HEXLOCK_PII_GITHUB_TOKEN, HEXLOCK_SUBTYPE_GITHUB_GHO},
        {"github_ghu", HEXLOCK_PII_GITHUB_TOKEN, HEXLOCK_SUBTYPE_GITHUB_GHU},
        {"github_ghs", HEXLOCK_PII_GITHUB_TOKEN, HEXLOCK_SUBTYPE_GITHUB_GHS},
        {"github_ghr", HEXLOCK_PII_GITHUB_TOKEN, HEXLOCK_SUBTYPE_GITHUB_GHR},
        {"aws_access_key", HEXLOCK_PII_AWS_ACCESS_KEY,
         HEXLOCK_SUBTYPE_AWS_ACCESS_KEY},
        {"anthropic_api", HEXLOCK_PII_ANTHROPIC_KEY,
         HEXLOCK_SUBTYPE_ANTHROPIC_API},
        {"anthropic_oat", HEXLOCK_PII_ANTHROPIC_KEY,
         HEXLOCK_SUBTYPE_ANTHROPIC_OAT},
        {"aws_secret_key", HEXLOCK_PII_AWS_SECRET_KEY,  // keep this at the end so it doesn't match other patterns
         HEXLOCK_SUBTYPE_AWS_SECRET_KEY},
};

/*
 * Builds a single alternation pattern from all enabled PII types
 * Disabled types (HEXLOCK_FLAG_DISABLED) are skipped entirely
 * Caller is responsible for freeing the returned string
 */
static char *build_pattern(const hexlock_route_t *routes) {
	// individual patterns mapped to their type
	static const struct {
		const char *pattern;
		hexlock_pii_type_t type;
	} all_patterns[] = {
	        {PATTERN_EMAIL, HEXLOCK_PII_EMAIL},
	        {PATTERN_SSN, HEXLOCK_PII_SSN},
	        {PATTERN_CREDIT_CARD, HEXLOCK_PII_CREDIT_CARD},
	        {PATTERN_IP_ADDRESS, HEXLOCK_PII_IP_ADDRESS},
	        {PATTERN_ROUTING_NUMBER, HEXLOCK_PII_ROUTING_NUMBER},
	        {PATTERN_PASSPORT, HEXLOCK_PII_PASSPORT},
	        {PATTERN_DRIVERS_LICENSE, HEXLOCK_PII_DRIVERS_LICENSE},
	        {PATTERN_BANK_ACCOUNT, HEXLOCK_PII_BANK_ACCOUNT},
	        {PATTERN_PHONE_PAREN, HEXLOCK_PII_PHONE},
	        {PATTERN_PHONE_DASH, HEXLOCK_PII_PHONE},
	        {PATTERN_PHONE_DOT, HEXLOCK_PII_PHONE},
	        {PATTERN_PHONE_SPACE, HEXLOCK_PII_PHONE},
	        {PATTERN_PHONE_BARE, HEXLOCK_PII_PHONE},
	        {PATTERN_GITHUB_GHP, HEXLOCK_PII_GITHUB_TOKEN},
	        {PATTERN_GITHUB_GHO, HEXLOCK_PII_GITHUB_TOKEN},
	        {PATTERN_GITHUB_GHU, HEXLOCK_PII_GITHUB_TOKEN},
	        {PATTERN_GITHUB_GHS, HEXLOCK_PII_GITHUB_TOKEN},
	        {PATTERN_GITHUB_GHR, HEXLOCK_PII_GITHUB_TOKEN},
	        {PATTERN_AWS_ACCESS_KEY, HEXLOCK_PII_AWS_ACCESS_KEY},
	        {PATTERN_ANTHROPIC_API, HEXLOCK_PII_ANTHROPIC_KEY},
	        {PATTERN_ANTHROPIC_OAT, HEXLOCK_PII_ANTHROPIC_KEY},
	        {PATTERN_AWS_SECRET_KEY, HEXLOCK_PII_AWS_SECRET_KEY},  // keep this at the end so it doesn't match other patterns
	};
	size_t count = sizeof(all_patterns) / sizeof(all_patterns[0]);

	// calculate total length needed
	size_t total = 1;  // null terminator
	for (size_t i = 0; i < count; i++) {
		if (routes[all_patterns[i].type].flags &
		    HEXLOCK_FLAG_DISABLED) {
			continue;
		}
		total += strlen(all_patterns[i].pattern) +
		         1;  // +1 for | , XXX one byte over not a problem
	}

	char *buf = malloc(total);
	if (!buf) {
		return NULL;
	}

	buf[0] = '\0';
	int first = 1;

	for (size_t i = 0; i < count; i++) {
		if (routes[all_patterns[i].type].flags &
		    HEXLOCK_FLAG_DISABLED) {
			continue;
		}
		if (!first) {
			strcat(buf, "|");
		}
		strcat(buf, all_patterns[i].pattern);
		first = 0;
	}

	return buf;
}

/*
 * init the regexes by compiling them
 */
hexlock_err_t hexlock_regex_init(hexlock_regex_ctx_t **ctx,
                                 const hexlock_route_t *routes) {
	if (!ctx || !routes) {
		return HEXLOCK_ERR_INTERNAL;
	}

	hexlock_regex_ctx_t *c = calloc(1, sizeof(*c));
	if (!c) {
		return HEXLOCK_ERR_NOMEM;
	}

	// build combined pattern
	char *pattern = build_pattern(routes);
	if (!pattern) {
		free(c);
		return HEXLOCK_ERR_NOMEM;
	}

	// compile pattern
	int errcode;
	PCRE2_SIZE erroffset;

	c->pattern = pcre2_compile((PCRE2_SPTR)pattern, PCRE2_ZERO_TERMINATED,
	                           PCRE2_UTF, &errcode, &erroffset, NULL);

	free(pattern);

	if (!c->pattern) {
		free(c);
		return HEXLOCK_ERR_REGEX;
	}

	// get capture count
	pcre2_pattern_info(c->pattern, PCRE2_INFO_CAPTURECOUNT,
	                   &c->capture_count);

	pcre2_pattern_info(c->pattern, PCRE2_INFO_NAMECOUNT, &c->name_count);
	pcre2_pattern_info(c->pattern, PCRE2_INFO_NAMEENTRYSIZE,
	                   &c->name_entry_size);
	pcre2_pattern_info(c->pattern, PCRE2_INFO_NAMETABLE, &c->name_table);

	// allocate match data — reused across scans
	c->match_data = pcre2_match_data_create_from_pattern(c->pattern, NULL);
	if (!c->match_data) {
		pcre2_code_free(c->pattern);
		free(c);
		return HEXLOCK_ERR_NOMEM;
	}

	*ctx = c;
	return HEXLOCK_OK;
}

/*
 * frees regex ctx
 */
void hexlock_regex_free(hexlock_regex_ctx_t *ctx) {
	if (!ctx) {
		return;
	}
	if (ctx->match_data) {
		pcre2_match_data_free(ctx->match_data);
	}
	if (ctx->pattern) {
		pcre2_code_free(ctx->pattern);
	}
	free(ctx);
}

/*
 * this function takes in a name of a PII pattern
 * and returns a type and s subtype
 */
static int name_to_type_and_subtype(const char *name, size_t name_len,
                                    hexlock_pii_type_t *type,
                                    hexlock_subtype_t *subtype) {
	for (size_t i = 0; i < PATTERN_TABLE_COUNT; i++) {
		if (strncmp(pattern_table[i].name, name, name_len) == 0 &&
		    pattern_table[i].name[name_len] == '\0') {
			*type = pattern_table[i].type;
			*subtype = pattern_table[i].subtype;
			return 0;
		}
	}
	return -1;
}

/*
 * scans input
 * it basically finds all the PII
 * match records their location in the string via offsets
 */
hexlock_err_t hexlock_regex_scan(hexlock_regex_ctx_t *ctx, const char *input,
                                 size_t length, hexlock_match_t **out_matches,
                                 size_t *out_count) {
	if (!ctx || !input || !out_matches || !out_count) {
		return HEXLOCK_ERR_INTERNAL;
	}

	*out_matches = NULL;
	*out_count = 0;

	// initial allocation — grown as needed
	size_t capacity = 16;
	size_t count = 0;
	hexlock_match_t *matches = malloc(capacity * sizeof(hexlock_match_t));
	if (!matches) {
		return HEXLOCK_ERR_NOMEM;
	}

	PCRE2_SIZE offset = 0;

	while (offset < length) {
		int rc = pcre2_match(ctx->pattern, (PCRE2_SPTR)input, length,
		                     offset, 0, ctx->match_data, NULL);

		if (rc == PCRE2_ERROR_NOMATCH) {
			break;
		}

		if (rc < 0) {
			free(matches);
			return HEXLOCK_ERR_REGEX;
		}

		PCRE2_SIZE *ovector =
		        pcre2_get_ovector_pointer(ctx->match_data);

		// find which named group matched
		hexlock_pii_type_t type =
		        HEXLOCK_PII_COUNT;  // means unknown or no type found
		                            // i.e. not a valid type
		hexlock_subtype_t subtype = HEXLOCK_SUBTYPE_NONE;

		PCRE2_UCHAR *entry = ctx->name_table;
		for (uint32_t i = 0; i < ctx->name_count; i++) {
			uint32_t group_num = (entry[0] << 8) | entry[1];

			if (ovector[2 * group_num] == PCRE2_UNSET) {
				entry += ctx->name_entry_size;
				continue;
			}

			const char *group_name = (const char *)(entry + 2);
			if (name_to_type_and_subtype(group_name,
			                             strlen(group_name), &type,
			                             &subtype) == 0) {
				break;
			}

			entry += ctx->name_entry_size;
		}

		if (type == HEXLOCK_PII_COUNT) {
			// unknown group — skip and advance
			offset = ovector[1];
			continue;
		}

		// grow matches array if needed
		if (count >= capacity) {
			capacity *= 2;
			hexlock_match_t *tmp = realloc(
			        matches, capacity * sizeof(hexlock_match_t));
			if (!tmp) {
				free(matches);
				return HEXLOCK_ERR_NOMEM;
			}
			matches = tmp;
		}

		matches[count].type = type;
		matches[count].subtype = subtype;
		matches[count].start = ovector[0];
		matches[count].end = ovector[1];
		count++;

		/* advance past this match, guard against zero length match */
		if (ovector[1] == offset) {
			offset++;
		} else {
			offset = ovector[1];
		}
	}

	*out_matches = matches;
	*out_count = count;
	return HEXLOCK_OK;
}

/*
 * Free matches
 */
void hexlock_matches_free(hexlock_match_t *matches, size_t count) {
	(void)count;
	free(matches);
}
