# Configuration

hexlock ships with secure defaults. Most users never need to touch configuration.
You probably should not be changing the configuration unless you are really
certain you need it.

The default behavior for each PII type is:

| Type             | Algorithm  |
|------------------|------------|
| email            | tokenize   |
| phone            | fpe        |
| ssn              | fpe        |
| credit_card      | fpe        |
| name             | tokenize   |
| address          | tokenize   |
| ip_address       | fpe        |
| passport         | fpe        |
| routing_number   | fpe        |
| bank_account     | fpe        |
| drivers_license  | fpe        |
| github tokens    | fpe        |
| AWS access id    | fpe        |
| AWS secret key   | fpe        |
| Anthropic keys   | fpe        |

**FPE** (format-preserving encryption) transforms the value in place while keeping
its format intact. A phone number stays a phone number, an SSN stays an SSN.
The original can be recovered with the same key.

**Tokenize** replaces the value with a synthetic substitute (e.g. a fake email
address). The original is stored in the session and recovered via lookup.

---

## Overriding defaults

Pass a `config` dict to `Client` to override specific routes. Only the types
you specify are affected. Everything else keeps its default.

```python
import hexlock

client = hexlock.Client(config={
    "routes": [
        {"type": "email", "algo": "fpe"},
    ]
})
```

### Disabling a PII type

To prevent hexlock from detecting or transforming a specific type entirely:

```python
client = hexlock.Client(config={
    "routes": [
        {"type": "name", "disabled": True},
        {"type": "address", "disabled": True},
    ]
})
```

Disabled types are passed through unchanged.

### Changing the algorithm

To switch a type from its default algorithm to the other:

```python
client = hexlock.Client(config={
    "routes": [
        {"type": "email", "algo": "fpe"},       # default is tokenize
        {"type": "phone", "algo": "tokenize"},  # default is fpe
    ]
})
```

### Combining options

```python
client = hexlock.Client(config={
    "routes": [
        {"type": "email",   "algo": "fpe"},
        {"type": "name",    "disabled": True},
        {"type": "address", "disabled": True},
    ]
})
```

---

## Route schema

Each entry in `routes` is a dict with the following fields:

| Field      | Type   | Required | Description                                      |
|------------|--------|----------|--------------------------------------------------|
| `type`     | string | yes      | PII type name (see table above)                  |
| `algo`     | string | no       | `"fpe"` or `"tokenize"`                          |
| `disabled` | bool   | no       | If `true`, this PII type is not detected or transformed |

`algo` and `disabled` are mutually exclusive in intent. Setting `disabled: true`
makes `algo` irrelevant.

---

## Valid type names

`email`, `phone`, `ssn`, `credit_card`, `name`, `address`,
`ip_address`, `passport`, `routing_number`, `bank_account`, `drivers_license`

---

## Notes

- Config is validated at `Client` initialization. Invalid type names or algo
  values raise `ValueError` immediately.
- Config is not persisted in `save_session()`, it is the caller's
  responsibility to pass the same config when restoring a session, since the
  session blob only stores the lookup table, not the routing rules.
- The `config` parameter is optional. Omitting it is equivalent to passing
  `{"routes": []}`.
