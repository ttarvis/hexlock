"""
hexlock.Client — friendly Python API for PII anonymization.

Basic usage (ephemeral session):
    client = hexlock.Client()
    anonymized = client.anonymize("call me at 234-555-6666")
    original = client.deanonymize(llm_output)

Persistent session (cross-session decryption):
    key = hexlock.generate_key()
    client = hexlock.Client(key=key)
    anonymized = client.anonymize("call me at 234-555-6666")
    blob = client.save_session()
    # store key and blob however you want

    # later, in a new process
    client = hexlock.Client(key=key, session=blob)
    original = client.deanonymize(llm_output)
"""

import hashlib
import json
import os
import secrets

from . import _bindings as _b

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    _HAS_CRYPTOGRAPHY = True
except ImportError:
    _HAS_CRYPTOGRAPHY = False


# ---------------------------------------------------------------------------
# Public constants — re-exported so users don't need to import _bindings
# ---------------------------------------------------------------------------

ALGO_FPE      = _b.ALGO_FPE
ALGO_TOKENIZE = _b.ALGO_TOKENIZE

PII_EMAIL           = _b.PII_EMAIL
PII_PHONE           = _b.PII_PHONE
PII_SSN             = _b.PII_SSN
PII_CREDIT_CARD     = _b.PII_CREDIT_CARD
PII_NAME            = _b.PII_NAME
PII_ADDRESS         = _b.PII_ADDRESS
PII_DATE_OF_BIRTH   = _b.PII_DATE_OF_BIRTH
PII_IP_ADDRESS      = _b.PII_IP_ADDRESS
PII_PASSPORT        = _b.PII_PASSPORT
PII_ROUTING_NUMBER  = _b.PII_ROUTING_NUMBER
PII_BANK_ACCOUNT    = _b.PII_BANK_ACCOUNT
PII_DRIVERS_LICENSE = _b.PII_DRIVERS_LICENSE

# String → PII type constant, used when parsing config dicts
_PII_NAMES = {
    "email":           _b.PII_EMAIL,
    "phone":           _b.PII_PHONE,
    "ssn":             _b.PII_SSN,
    "credit_card":     _b.PII_CREDIT_CARD,
    "name":            _b.PII_NAME,
    "address":         _b.PII_ADDRESS,
    "ip_address":      _b.PII_IP_ADDRESS,
    "passport":        _b.PII_PASSPORT,
    "routing_number":  _b.PII_ROUTING_NUMBER,
    "bank_account":    _b.PII_BANK_ACCOUNT,
    "drivers_license": _b.PII_DRIVERS_LICENSE,
}

_ALGO_NAMES = {
    "fpe":      _b.ALGO_FPE,
    "tokenize": _b.ALGO_TOKENIZE,
}

# Compatibility constraints — encodes real design limits, not temporary gaps.
# Email, name, and address have variable structure that FPE cannot preserve
# meaningfully; they are tokenize-only permanently.
# All numeric/fixed-format types support FPE; most also support tokenize.
_FPE_SUPPORTED = {
    _b.PII_PHONE,
    _b.PII_SSN,
    _b.PII_CREDIT_CARD,
    _b.PII_DATE_OF_BIRTH,
    _b.PII_IP_ADDRESS,
    _b.PII_PASSPORT,
    _b.PII_ROUTING_NUMBER,
    _b.PII_BANK_ACCOUNT,
    _b.PII_DRIVERS_LICENSE,
}

_TOKENIZE_SUPPORTED = {
    _b.PII_EMAIL,
    _b.PII_PHONE,
    _b.PII_SSN,
    _b.PII_NAME,
    _b.PII_ADDRESS,
}

# Human-readable names for error messages
_PII_ALGO_SUPPORT = {
    "email":           "tokenize only",
    "phone":           "fpe or tokenize",
    "ssn":             "fpe or tokenize",
    "credit_card":     "fpe only",
    "name":            "tokenize only",
    "address":         "tokenize only",
    "ip_address":      "fpe only",
    "passport":        "fpe only",
    "routing_number":  "fpe only",
    "bank_account":    "fpe only",
    "drivers_license": "fpe only",
}


def _parse_config(config: dict) -> list:
    """
    Parse a config dict into a list of _bindings.Route structs.

    Expected shape:
        {
            "routes": [
                {"type": "ssn", "disabled": True},
                {"type": "email", "algo": "fpe"},
            ]
        }

    Only keys present in each route entry are applied — everything else
    inherits from the C-side defaults.
    """
    raw_routes = config.get("routes", [])
    if not isinstance(raw_routes, list):
        raise ValueError("config 'routes' must be a list")

    routes = []
    for entry in raw_routes:
        type_name = entry.get("type")
        if type_name not in _PII_NAMES:
            raise ValueError(
                f"unknown PII type '{type_name}'. "
                f"Valid types: {', '.join(_PII_NAMES)}"
            )

        pii_type = _PII_NAMES[type_name]
        flags = _b.FLAG_NONE

        if entry.get("disabled", False):
            flags |= _b.FLAG_DISABLED

        algo_name = entry.get("algo")
        if algo_name is not None:
            if algo_name not in _ALGO_NAMES:
                raise ValueError(
                    f"unknown algo '{algo_name}'. "
                    f"Valid options: {', '.join(_ALGO_NAMES)}"
                )
            algo = _ALGO_NAMES[algo_name]

            # validate compatibility — catch misconfigurations at init time
            # rather than letting them surface as internal errors during processing
            if algo == _b.ALGO_FPE and pii_type not in _FPE_SUPPORTED:
                raise ValueError(
                    f"'{type_name}' does not support FPE "
                    f"({_PII_ALGO_SUPPORT[type_name]})"
                )
            if algo == _b.ALGO_TOKENIZE and pii_type not in _TOKENIZE_SUPPORTED:
                raise ValueError(
                    f"'{type_name}' does not support tokenization "
                    f"({_PII_ALGO_SUPPORT[type_name]})"
                )
        else:
            # algo not specified — use 0 as a placeholder; C merges with
            # defaults so the unspecified algo won't override anything
            # unless disabled is set, in which case algo is irrelevant.
            algo = _b.ALGO_FPE  # C default for this slot; flags carry intent

        route = _b.Route()
        route.type    = pii_type
        route.algo    = algo
        route.flags   = flags
        route.options = None
        routes.append(route)

    return routes


def generate_key() -> bytes:
    """Generate a cryptographically secure 32-byte key."""
    return secrets.token_bytes(32)


def _derive_keys(master_key: bytes):
    """
    Derive two distinct keys from the master key.
    fpe_key     → passed to C for FPE/CMAC operations
    session_key → used to encrypt/decrypt the session blob in Python
    """
    fpe_key     = hashlib.sha256(master_key + b'\x00').digest()
    session_key = hashlib.sha256(master_key + b'\x01').digest()
    return fpe_key, session_key


class Client:
    """
    hexlock Client — anonymizes PII in text for safe LLM processing.

    Ephemeral (no persistence across sessions):
        client = Client()

    Persistent (cross-session decryption):
        key = hexlock.generate_key()
        client = Client(key=key)
        blob = client.save_session()  # store alongside key

        # restore later
        client = Client(key=key, session=blob)
    """

    def __init__(self, key: bytes = None, session: bytes = None,
                 config: dict = None):
        """
        Initialize a hexlock client.

        key:     32-byte master key. If not provided a random ephemeral
                 key is generated and the session cannot be restored later.
        session: encrypted session blob from a previous save_session() call.
                 Requires key to be provided.
        config:  optional dict to override default PII routing. See
                 docs/configuration.md for the full schema. Most users
                 should omit this and rely on the secure defaults.
        """
        if key is not None and len(key) != 32:
            raise ValueError("key must be exactly 32 bytes")

        if session is not None and key is None:
            raise ValueError("a key is required to restore a session")

        if config is not None and not isinstance(config, dict):
            raise TypeError("config must be a dict")

        self._ephemeral = key is None
        self._master_key = key if key is not None else generate_key()
        self._fpe_key, self._session_key = _derive_keys(self._master_key)

        # parse config into Route structs before initializing C context
        routes = _parse_config(config) if config else None

        # initialize C context with the derived FPE key and any route overrides
        self._ctx = _b.init(self._fpe_key, routes)

        # lookup table: transformed string → (algo, pii_type, subtype, original)
        # original is only populated for tokenized values
        self._lookup: dict = {}

        if session is not None:
            self._load_session(session)

    def anonymize(self, text: str) -> str:
        """
        Scan text for PII and replace it with anonymized values.
        Returns the anonymized string.
        Original values are stored internally for deanonymization.
        """
        if not isinstance(text, str):
            raise TypeError("text must be a string")

        output, raw_records = _b.process(self._ctx, text)

        for rec in raw_records:
            transformed = rec["transformed"].decode("utf-8").rstrip('\x00')

            if rec["algo"] == _b.ALGO_TOKENIZE:
                original = rec["original"].decode("utf-8").rstrip('\x00')
            else:
                original = None  # FPE — recovered via C decrypt, not stored

            self._lookup[transformed] = {
                "algo":     rec["algo"],
                "pii_type": rec["type"],
                "subtype":  rec["subtype"],
                "original": original,
            }

        return output

    def deanonymize(self, text: str) -> str:
        """
        Scan text for anonymized values and restore the originals.
        Returns the restored string.
        """
        if not isinstance(text, str):
            raise TypeError("text must be a string")

        result = text

        # sort by length descending to avoid partial replacements
        for transformed, record in sorted(
            self._lookup.items(), key=lambda x: len(x[0]), reverse=True
        ):
            if transformed not in result:
                continue

            if record["algo"] == _b.ALGO_FPE:
                original = _b.decrypt(
                    self._ctx,
                    transformed,
                    record["pii_type"],
                    record["subtype"],
                )
            else:
                original = record["original"]

            result = result.replace(transformed, original)

        return result

    def save_session(self) -> bytes:
        """
        Export the current session state as an encrypted blob.
        Store this alongside your key to enable cross-session deanonymization.
        Returns bytes.

        Raises RuntimeError if the cryptography package is not installed.
        """
        if not _HAS_CRYPTOGRAPHY:
            raise RuntimeError(
                "save_session() requires the 'cryptography' package. "
                "Install it with: pip install hexlock[persistent]"
            )

        plaintext = json.dumps(self._lookup).encode("utf-8")

        aesgcm = AESGCM(self._session_key)
        nonce  = secrets.token_bytes(12)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)

        # prepend nonce — needed for decryption
        return nonce + ciphertext

    def _load_session(self, blob: bytes):
        """Decrypt and restore session state from a blob."""
        if not _HAS_CRYPTOGRAPHY:
            raise RuntimeError(
                "restoring a session requires the 'cryptography' package. "
                "Install it with: pip install hexlock[persistent]"
            )

        if len(blob) < 13:
            raise ValueError("invalid session blob")

        nonce      = blob[:12]
        ciphertext = blob[12:]

        aesgcm = AESGCM(self._session_key)
        try:
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        except Exception:
            raise ValueError(
                "session decryption failed — "
                "ensure you are using the same key that created this session"
            )

        self._lookup = json.loads(plaintext.decode("utf-8"))

    def __del__(self):
        """Free the C context when the client is garbage collected."""
        if hasattr(self, "_ctx") and self._ctx:
            _b.free(self._ctx)
            self._ctx = None
