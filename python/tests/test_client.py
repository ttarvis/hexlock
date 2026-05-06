"""
Tests for hexlock.Client
"""

import pytest
import hexlock


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def client():
    return hexlock.Client()


@pytest.fixture
def keyed_client():
    key = hexlock.generate_key()
    return hexlock.Client(key=key), key


# ---------------------------------------------------------------------------
# generate_key
# ---------------------------------------------------------------------------

def test_generate_key_length():
    key = hexlock.generate_key()
    assert len(key) == 32

def test_generate_key_random():
    assert hexlock.generate_key() != hexlock.generate_key()


# ---------------------------------------------------------------------------
# Client init
# ---------------------------------------------------------------------------

def test_client_ephemeral():
    client = hexlock.Client()
    assert client is not None

def test_client_with_key():
    key = hexlock.generate_key()
    client = hexlock.Client(key=key)
    assert client is not None

def test_client_bad_key_length():
    with pytest.raises(ValueError):
        hexlock.Client(key=b"tooshort")

def test_client_session_without_key():
    with pytest.raises(ValueError):
        hexlock.Client(session=b"somebytes")


# ---------------------------------------------------------------------------
# anonymize
# ---------------------------------------------------------------------------

def test_anonymize_phone_dash(client):
    result = client.anonymize("call me at 234-555-6666")
    assert "234-555-6666" not in result
    assert result != ""

def test_anonymize_phone_format_preserved(client):
    result = client.anonymize("call me at 234-555-6666")
    # find the transformed phone in the output
    parts = result.split()
    phone = parts[-1]
    assert phone[3] == '-'
    assert phone[7] == '-'

def test_anonymize_ssn(client):
    result = client.anonymize("my ssn is 123-45-6789")
    assert "123-45-6789" not in result

def test_anonymize_credit_card(client):
    result = client.anonymize("card 4111-1111-1111-1111")
    assert "4111-1111-1111-1111" not in result

def test_anonymize_email(client):
    result = client.anonymize("email me at john.smith@gmail.com")
    assert "john.smith@gmail.com" not in result
    assert "@" in result

def test_anonymize_ip(client):
    result = client.anonymize("server at 192.168.1.1 is down")
    assert "192.168.1.1" not in result

def test_anonymize_github_token(client):
    result = client.anonymize("token ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef1234")
    assert "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef12" not in result
    assert "ghp_" in result  # prefix preserved

def test_anonymize_aws_access_key(client):
    result = client.anonymize("key AKIAABCD2345EFGH2367")
    assert "AKIAIOSFODNN7EXAMPLE" not in result
    assert "AKIA" in result

def test_anonymize_aws_secret_key(client):
    result = client.anonymize("secret wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
    assert "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY1" not in result

def test_anonymize_anthropic_key(client):
    result = client.anonymize("key sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnop123456")
    assert "sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnop123456" not in result
    assert "sk-ant-api03-" in result

def test_anonymize_no_pii(client):
    text = "hello world nothing to see here"
    result = client.anonymize(text)
    assert result == text

def test_anonymize_multiple(client):
    text = "call 234-555-6666 or email john.smith@gmail.com"
    result = client.anonymize(text)
    assert "234-555-6666" not in result
    assert "john.smith@gmail.com" not in result

def test_anonymize_deterministic():
    key = hexlock.generate_key()
    c1 = hexlock.Client(key=key)
    c2 = hexlock.Client(key=key)
    text = "call me at 234-555-6666"
    assert c1.anonymize(text) == c2.anonymize(text)

def test_anonymize_returns_string(client):
    assert isinstance(client.anonymize("call me at 234-555-6666"), str)

def test_anonymize_type_error(client):
    with pytest.raises(TypeError):
        client.anonymize(12345)


# ---------------------------------------------------------------------------
# deanonymize
# ---------------------------------------------------------------------------

def test_deanonymize_phone(client):
    original = "call me at 234-555-6666"
    anonymized = client.anonymize(original)
    restored = client.deanonymize(anonymized)
    assert restored == original

def test_deanonymize_email(client):
    original = "email me at john.smith@gmail.com"
    anonymized = client.anonymize(original)
    restored = client.deanonymize(anonymized)
    assert restored == original

def test_deanonymize_ssn(client):
    original = "my ssn is 123-45-6789"
    anonymized = client.anonymize(original)
    restored = client.deanonymize(anonymized)
    assert restored == original

def test_deanonymize_github_token(client):
    original = "my token is ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef12"
    anonymized = client.anonymize(original)
    restored = client.deanonymize(anonymized)
    assert restored == original

def test_deanonymize_aws_access_key(client):
    original = "access key AKIAIOSFODNN7EXAMPLE123456"
    anonymized = client.anonymize(original)
    restored = client.deanonymize(anonymized)
    assert restored == original

def test_deanonymize_anthropic_key(client):
    original = "export ANTHROPIC_API_KEY=sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnop"
    anonymized = client.anonymize(original)
    restored = client.deanonymize(anonymized)
    assert restored == original

def test_deanonymize_multiple(client):
    original = "call 234-555-6666 or email john.smith@gmail.com"
    anonymized = client.anonymize(original)
    restored = client.deanonymize(anonymized)
    assert restored == original

def test_deanonymize_no_pii(client):
    text = "hello world"
    assert client.deanonymize(text) == text

def test_deanonymize_type_error(client):
    with pytest.raises(TypeError):
        client.deanonymize(12345)


# ---------------------------------------------------------------------------
# save_session / restore
# ---------------------------------------------------------------------------

def test_save_session_returns_bytes():
    pytest.importorskip("cryptography")
    key = hexlock.generate_key()
    client = hexlock.Client(key=key)
    client.anonymize("call me at 234-555-6666")
    blob = client.save_session()
    assert isinstance(blob, bytes)
    assert len(blob) > 0

def test_save_session_restore_fpe():
    pytest.importorskip("cryptography")
    key = hexlock.generate_key()
    original = "call me at 234-555-6666"

    c1 = hexlock.Client(key=key)
    anonymized = c1.anonymize(original)
    blob = c1.save_session()

    c2 = hexlock.Client(key=key, session=blob)
    restored = c2.deanonymize(anonymized)
    assert restored == original

def test_save_session_restore_tokenized():
    pytest.importorskip("cryptography")
    key = hexlock.generate_key()
    original = "email john.smith@gmail.com please"

    c1 = hexlock.Client(key=key)
    anonymized = c1.anonymize(original)
    blob = c1.save_session()

    c2 = hexlock.Client(key=key, session=blob)
    restored = c2.deanonymize(anonymized)
    assert restored == original

def test_save_session_wrong_key():
    pytest.importorskip("cryptography")
    key1 = hexlock.generate_key()
    key2 = hexlock.generate_key()

    c1 = hexlock.Client(key=key1)
    c1.anonymize("call me at 234-555-6666")
    blob = c1.save_session()

    with pytest.raises(ValueError):
        hexlock.Client(key=key2, session=blob)

def test_save_session_ephemeral_client():
    pytest.importorskip("cryptography")
    client = hexlock.Client()
    client.anonymize("call me at 234-555-6666")
    # ephemeral client can still save — blob is encrypted, just key is ephemeral
    blob = client.save_session()
    assert isinstance(blob, bytes)
