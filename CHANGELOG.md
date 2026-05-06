# CHANGELOG.md

## 0.2.0

### Features:

 - Added FPE for GitHub classic tokens (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`)
 - Added FPE for AWS access key IDs (`AKIA` prefix)
 - Added FPE for AWS secret access keys
 - Added FPE for Anthropic API keys and OAuth tokens (`sk-ant-api03-`, `sk-ant-oat01-` prefixes)

### Changes:
 - Expanded `transformed` and `original` fields in `hexlock_token_record_t` from 64 to 256 bytes to accommodate longer token types
 - Updated Python bindings with new PII type and subtype constants and corrected struct size assertion
