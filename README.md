# hexlock

Protection for PII and sensitive data in LLM pipelines.

**[hexlock.xyz](https://hexlock.xyz)**

## What is it?

Hexlock is a tool for preventing sensitive data from being used with LLMs.
It replaces sensitive data but preserves the format so the LLM understands it still. 
Then it  rehydrates the response with the original data. The sensitive data never gets
sent to the LLM.

Data types protected include email, phone, SSNs, driver's license identifiers, 
passport IDs, credit card, GitHub tokens, Anthropic tokens, AWS keys, and more.
See [CONFIG](https://github.com/ttarvis/hexlock/blob/master/docs/configuration.md) for more types.

## Install

```bash
pip install hexlock
```

## Usage

```python
import hexlock

# ephemeral — no key needed, deanonymize in the same session
client = hexlock.Client()
anonymized = client.anonymize(
    "You can each me at jane.smith@acme.com or 415-555-0192."
)
original = client.deanonymize(llm_response)

# persistent — save and restore across sessions
key = hexlock.generate_key()  # store this securely
client = hexlock.Client(key=key)
anonymized = client.anonymize(
    "My credit card number is 4111 1111 1111 1111"
)
blob = client.save_session()  # store this alongside your key

# later, in a new process
client = hexlock.Client(key=key, session=blob)
original = client.deanonymize(llm_response)
```

## Configuration

see [CONFIG](docs/configuration.md)
