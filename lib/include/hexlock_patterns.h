#ifndef HEXLOCK_PATTERNS_H
#define HEXLOCK_PATTERNS_H

/*
 * Internal header only
 * Regex patterns for PII detection
 * Named groups map directly to hexlock_pii_type_t enum values
 * To add a new pattern: add a #define here, add the type to the enum
 * add a routing table entry in router.c, add it to the alternation in regex.c
 */


/* 
 * EMAIL
 */
#define PATTERN_EMAIL \
    "(?P<email>[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,})"

/*
 * Phone (NANP)
 * multiple patterns
 */
#define PATTERN_PHONE_PAREN \
    "(?P<phone_paren>\\(?\\d{3}\\)[\\s]\\d{3}-\\d{4})"

#define PATTERN_PHONE_DASH \
    "(?P<phone_dash>\\d{3}-\\d{3}-\\d{4})"

#define PATTERN_PHONE_DOT \
    "(?P<phone_dot>\\d{3}\\.\\d{3}\\.\\d{4})"

#define PATTERN_PHONE_SPACE \
    "(?P<phone_space>\\d{3}\\s\\d{3}\\s\\d{4})"

#define PATTERN_PHONE_BARE \
    "(?P<phone_bare>\\d{10})"

/* 
 * SSN
 */

#define PATTERN_SSN \
    "(?P<ssn>\\d{3}-\\d{2}-\\d{4})"

/*
 * Credit card CC
 */

#define PATTERN_CREDIT_CARD \
    "(?P<credit_card>\\d{4}[\\s-]?\\d{4}[\\s-]?\\d{4}[\\s-]?\\d{4})"

/*
 * IP address (IPv4 only) 
 */

#define PATTERN_IP_ADDRESS \
    "(?P<ip_address>(?:(?:25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\.){3}" \
    "(?:25[0-5]|2[0-4]\\d|[01]?\\d\\d?))"

/*
 * Passport (US) 
 */

#define PATTERN_PASSPORT \
    "(?P<passport>[A-Z]{1,2}[0-9]{6,9})"

/* 
 * Routing number
 */

#define PATTERN_ROUTING_NUMBER \
    "(?P<routing_number>\\b[0-9]{9}\\b)"

/*
 * Bank account
 */

#define PATTERN_BANK_ACCOUNT \
    "(?P<bank_account>\\b[0-9]{8,17}\\b)"

/*
 * Driver's license (common US formats)
 */

#define PATTERN_DRIVERS_LICENSE \
    "(?P<drivers_license>[A-Z]{1,2}[0-9]{6,8})"
/*
 * GitHub classic token patterns
 */

#define PATTERN_GITHUB_GHP \
    "(?P<github_ghp>ghp_[A-Za-z0-9]{36})"

#define PATTERN_GITHUB_GHO \
    "(?P<github_gho>gho_[A-Za-z0-9]{36})"

#define PATTERN_GITHUB_GHU \
    "(?P<github_ghu>ghu_[A-Za-z0-9]{36})"

#define PATTERN_GITHUB_GHS \
    "(?P<github_ghs>ghs_[A-Za-z0-9]{36})"

#define PATTERN_GITHUB_GHR \
    "(?P<github_ghr>ghr_[A-Za-z0-9]{36})"

/*
 * AWS access key kid
 */
#define PATTERN_AWS_ACCESS_KEY \
    "(?P<aws_access_key>AKIA[A-Z2-7]{16})"

/*
 * AWS secret access key
 */
#define PATTERN_AWS_SECRET_KEY \
    "(?P<aws_secret_key>\\b[A-Za-z0-9/+]{40}\\b)"

/*
 * Anthropic API key
 * also OAuth token
 */
#define PATTERN_ANTHROPIC_API \
    "(?P<anthropic_api>sk-ant-api03-[A-Za-z0-9]{48})"

#define PATTERN_ANTHROPIC_OAT \
    "(?P<anthropic_oat>sk-ant-oat01-[A-Za-z0-9]{48})"

/*
 * JWT deferred to v0.3.0, see roadmap
 */
//#define PATTERN_JWT \
//    "(?P<jwt>eyJ[A-Za-z0-9_-]+\\.eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+)"

#endif
