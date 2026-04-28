# Roadmap for future releases

## v1 planned featuers

Some things are more urgent and some can wait. Bug fixes should be
prioritized. v1 should be stable and cover most use cases.

### improve PII types

By v1 I would like to have more PII types covered. These can be potential ideas.

* other types of passport data
* any missing financial data
* salaries/large monetary values?
* adding documentation for things
* dates? date of birth?
* perhaps adding support for other languages?

### NER

So this should cover detecting names, orgs, and places. I think we don't need
to focus on every language. Let's target Anglophone first and see what happens.
If there is large demand for other languages, then we can add that.

### dropping the cryptography dependency

I would really like to drop this. There is no reason to import that whole lib.

## v2 planned features

If not sooner

### target WASM

