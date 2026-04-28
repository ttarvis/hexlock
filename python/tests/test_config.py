"""
Tests for hexlock.Client config parameter.
"""

import pytest
import hexlock


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def client():
    return hexlock.Client()


# ---------------------------------------------------------------------------
# Config validation
# ---------------------------------------------------------------------------

def test_config_not_dict():
    with pytest.raises(TypeError):
        hexlock.Client(config="hexlock.yaml")

def test_config_bad_pii_type():
    with pytest.raises(ValueError):
        hexlock.Client(config={
            "routes": [{"type": "social_security", "disabled": True}]
        })

def test_config_bad_algo():
    with pytest.raises(ValueError):
        hexlock.Client(config={
            "routes": [{"type": "phone", "algo": "quantum"}]
        })

def test_config_empty_routes():
    # empty routes list is valid — equivalent to no config
    client = hexlock.Client(config={"routes": []})
    assert client is not None

def test_config_missing_routes_key():
    # missing 'routes' key — treated as empty, should not raise
    client = hexlock.Client(config={})
    assert client is not None


# ---------------------------------------------------------------------------
# Disabled types
# ---------------------------------------------------------------------------

def test_disabled_ssn_passes_through():
    client = hexlock.Client(config={
        "routes": [{"type": "ssn", "disabled": True}]
    })
    text = "my ssn is 123-45-6789"
    result = client.anonymize(text)
    assert "123-45-6789" in result

def test_disabled_phone_passes_through():
    client = hexlock.Client(config={
        "routes": [{"type": "phone", "disabled": True}]
    })
    text = "call me at 234-555-6666"
    result = client.anonymize(text)
    assert "234-555-6666" in result

def test_disabled_email_passes_through():
    client = hexlock.Client(config={
        "routes": [{"type": "email", "disabled": True}]
    })
    text = "email me at john.smith@gmail.com"
    result = client.anonymize(text)
    assert "john.smith@gmail.com" in result

def test_disabled_type_not_in_lookup():
    # disabled types should not appear in the lookup table
    client = hexlock.Client(config={
        "routes": [{"type": "ssn", "disabled": True}]
    })
    client.anonymize("my ssn is 123-45-6789")
    assert len(client._lookup) == 0

def test_disabled_one_type_others_still_work():
    client = hexlock.Client(config={
        "routes": [{"type": "ssn", "disabled": True}]
    })
    text = "ssn 123-45-6789 and phone 234-555-6666"
    result = client.anonymize(text)
    assert "123-45-6789" in result       # SSN passes through
    assert "234-555-6666" not in result  # phone still anonymized

def test_disabled_roundtrip():
    # deanonymize should return text unchanged when the only PII is disabled
    client = hexlock.Client(config={
        "routes": [{"type": "ssn", "disabled": True}]
    })
    text = "my ssn is 123-45-6789"
    anonymized = client.anonymize(text)
    restored = client.deanonymize(anonymized)
    assert restored == text


# ---------------------------------------------------------------------------
# Algorithm overrides
# ---------------------------------------------------------------------------

def test_email_algo_fpe_rejected():
    # email is tokenize-only — FPE must be caught at init time, not processing time
    with pytest.raises(ValueError, match="does not support FPE"):
        hexlock.Client(config={
            "routes": [{"type": "email", "algo": "fpe"}]
        })

def test_credit_card_algo_tokenize_rejected():
    # credit_card is fpe-only
    with pytest.raises(ValueError, match="does not support tokenization"):
        hexlock.Client(config={
            "routes": [{"type": "credit_card", "algo": "tokenize"}]
        })

def test_phone_algo_tokenize_roundtrip():
    # phone supports both — switching from default fpe to tokenize
    client = hexlock.Client(config={
        "routes": [{"type": "phone", "algo": "tokenize"}]
    })
    original = "call me at 234-555-6666"
    anonymized = client.anonymize(original)
    assert "234-555-6666" not in anonymized
    restored = client.deanonymize(anonymized)
    assert restored == original

def test_ssn_algo_tokenize_roundtrip():
    # ssn supports both — switching from default fpe to tokenize
    client = hexlock.Client(config={
        "routes": [{"type": "ssn", "algo": "tokenize"}]
    })
    original = "my ssn is 123-45-6789"
    anonymized = client.anonymize(original)
    assert "123-45-6789" not in anonymized
    restored = client.deanonymize(anonymized)
    assert restored == original


# ---------------------------------------------------------------------------
# Multiple overrides
# ---------------------------------------------------------------------------

def test_multiple_overrides():
    client = hexlock.Client(config={
        "routes": [
            {"type": "phone", "algo": "tokenize"},
            {"type": "name",  "disabled": True},
        ]
    })
    assert client is not None

def test_multiple_overrides_roundtrip():
    client = hexlock.Client(config={
        "routes": [
            {"type": "ssn",   "disabled": True},
            {"type": "phone", "algo": "tokenize"},
        ]
    })
    original = "call 234-555-6666 ssn 123-45-6789"
    anonymized = client.anonymize(original)
    assert "234-555-6666" not in anonymized  # phone anonymized via tokenize
    assert "123-45-6789" in anonymized       # ssn disabled
    restored = client.deanonymize(anonymized)
    assert restored == original


# ---------------------------------------------------------------------------
# Config does not affect session blob
# ---------------------------------------------------------------------------

def test_session_restore_requires_same_config():
    """
    Config is not persisted in save_session(). A restored client must be
    initialized with the same config, otherwise disabled types that appear
    in new text won't match the lookup table from the original session.
    This test documents the behavior rather than asserting it as an error.
    """
    pytest.importorskip("cryptography")
    key = hexlock.generate_key()

    c1 = hexlock.Client(key=key, config={
        "routes": [{"type": "phone", "algo": "tokenize"}]
    })
    original = "call me at 234-555-6666"
    anonymized = c1.anonymize(original)
    blob = c1.save_session()

    # restore with same config — should work
    c2 = hexlock.Client(key=key, session=blob, config={
        "routes": [{"type": "phone", "algo": "tokenize"}]
    })
    restored = c2.deanonymize(anonymized)
    assert restored == original
