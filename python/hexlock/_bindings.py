"""
Low-level ctypes bindings to libhexlock.
Not intended for direct use — use Client instead.
"""

import ctypes
import ctypes.util
import os
import sys
from pathlib import Path


def _load_library():
    """Load libhexlock from the package _lib directory."""
    lib_dir = Path(__file__).parent / "_lib"
    
    if sys.platform == "darwin":
        name = "libhexlock.dylib"
    elif sys.platform == "linux":
        name = "libhexlock.so"
    else:
        raise OSError(f"Unsupported platform: {sys.platform}")
    
    path = lib_dir / name
    if not path.exists():
        raise OSError(f"libhexlock not found at {path}. Did you run make?")
    
    return ctypes.CDLL(str(path))


_lib = _load_library()


# Enums — mirrored as Python ints, constants defined here for convenience

# hexlock_pii_type_t
PII_EMAIL           = 0
PII_PHONE           = 1
PII_SSN             = 2
PII_CREDIT_CARD     = 3
PII_NAME            = 4
PII_ADDRESS         = 5
PII_DATE_OF_BIRTH   = 6
PII_IP_ADDRESS      = 7
PII_PASSPORT        = 8
PII_ROUTING_NUMBER  = 9
PII_BANK_ACCOUNT    = 10
PII_DRIVERS_LICENSE = 11

# hexlock_algorithm_t
ALGO_FPE      = 0
ALGO_TOKENIZE = 1

# hexlock_subtype_t
SUBTYPE_NONE             = 0
SUBTYPE_PHONE_PAREN      = 1
SUBTYPE_PHONE_DASH       = 2
SUBTYPE_PHONE_DOT        = 3
SUBTYPE_PHONE_SPACE      = 4
SUBTYPE_PHONE_BARE       = 5
SUBTYPE_SSN              = 6
SUBTYPE_CREDIT_CARD      = 7
SUBTYPE_IP_ADDRESS       = 8
SUBTYPE_PASSPORT         = 9
SUBTYPE_ROUTING_NUMBER   = 10
SUBTYPE_BANK_ACCOUNT     = 11
SUBTYPE_DRIVERS_LICENSE  = 12
SUBTYPE_EMAIL            = 13

# hexlock_err_t
ERR_OK           = 0
ERR_NOMEM        = -1
ERR_REGEX        = -2
ERR_INVALID_KEY  = -3
ERR_INVALID_TYPE = -4
ERR_INTERNAL     = -5


# Flags — mirror hexlock.h defines

FLAG_NONE             = 0x00000000
FLAG_PRESERVE_PREFIX  = 0x00000001
FLAG_PRESERVE_DOMAIN  = 0x00000002
FLAG_DISABLED         = 0x00000004


# Structs

class Route(ctypes.Structure):
    """Mirrors hexlock_route_t. Passed to hexlock_init() as an override array."""
    _fields_ = [
        ("type",    ctypes.c_int),
        ("algo",    ctypes.c_int),
        ("flags",   ctypes.c_uint32),
        ("options", ctypes.c_void_p),  # reserved, always NULL
    ]


class TokenRecord(ctypes.Structure):
    _fields_ = [
        ("type",        ctypes.c_int),    # hexlock_pii_type_t
        ("algo",        ctypes.c_int),    # hexlock_algorithm_t
        ("subtype",     ctypes.c_int),    # hexlock_subtype_t
        ("token_key",   ctypes.c_uint32),
        ("transformed", ctypes.c_char * 64),
        ("original",    ctypes.c_char * 256),
    ]


class Result(ctypes.Structure):
    _fields_ = [
        ("output",  ctypes.c_char_p),
        ("records", ctypes.POINTER(TokenRecord)),
        ("count",   ctypes.c_size_t),
    ]

# Assertions
# This is for making sure that if we change the C code
# Python requires a revision

assert ctypes.sizeof(TokenRecord) == 336, (
    f"TokenRecord size mismatch: expected 336, got {ctypes.sizeof(TokenRecord)}. "
    "Update _bindings.py to match the C struct."
)

# Function signatures

# hexlock_err_t hexlock_init(hexlock_ctx_t **ctx, const uint8_t *key,
#                            const hexlock_route_t *routes, size_t route_count)
_lib.hexlock_init.restype  = ctypes.c_int
_lib.hexlock_init.argtypes = [
    ctypes.POINTER(ctypes.c_void_p),  # ctx **
    ctypes.c_char_p,                   # key
    ctypes.c_void_p,                   # routes (NULL for defaults)
    ctypes.c_size_t,                   # route_count
]

# void hexlock_free(hexlock_ctx_t *ctx)
_lib.hexlock_free.restype  = None
_lib.hexlock_free.argtypes = [ctypes.c_void_p]

# hexlock_err_t hexlock_process(hexlock_ctx_t *ctx, const char *input,
#                               size_t length, hexlock_result_t **result)
_lib.hexlock_process.restype  = ctypes.c_int
_lib.hexlock_process.argtypes = [
    ctypes.c_void_p,                        # ctx
    ctypes.c_char_p,                        # input
    ctypes.c_size_t,                        # length
    ctypes.POINTER(ctypes.POINTER(Result)), # result **
]

# void hexlock_result_free(hexlock_result_t *result)
_lib.hexlock_result_free.restype  = None
_lib.hexlock_result_free.argtypes = [ctypes.POINTER(Result)]

# hexlock_err_t hexlock_decrypt(hexlock_ctx_t *ctx, char *buf, size_t length,
#                               hexlock_pii_type_t type, hexlock_subtype_t subtype)
_lib.hexlock_decrypt.restype  = ctypes.c_int
_lib.hexlock_decrypt.argtypes = [
    ctypes.c_void_p,  # ctx
    ctypes.POINTER(ctypes.c_char), # mutable buf
    ctypes.c_size_t,  # length
    ctypes.c_int,     # type
    ctypes.c_int,     # subtype
]


# Thin wrappers — raise on error, handle memory

class HexlockError(Exception):
    def __init__(self, code):
        self.code = code
        messages = {
            ERR_NOMEM:        "out of memory",
            ERR_REGEX:        "regex error",
            ERR_INVALID_KEY:  "invalid key",
            ERR_INVALID_TYPE: "invalid PII type",
            ERR_INTERNAL:     "internal error",
        }
        super().__init__(messages.get(code, f"unknown error {code}"))


def _check(err):
    if err != ERR_OK:
        raise HexlockError(err)


def init(key: bytes, routes: list = None) -> ctypes.c_void_p:
    """
    Initialize a hexlock context.
    key must be exactly 32 bytes.
    routes is an optional list of Route structs to override defaults.
    """
    if len(key) != 32:
        raise ValueError("key must be exactly 32 bytes")
    ctx = ctypes.c_void_p(None)
    if routes:
        arr = (Route * len(routes))(*routes)
        _check(_lib.hexlock_init(
            ctypes.byref(ctx),
            key,
            arr,
            len(routes),
        ))
    else:
        _check(_lib.hexlock_init(
            ctypes.byref(ctx),
            key,
            None,
            0,
        ))
    return ctx


def free(ctx: ctypes.c_void_p):
    """Free a hexlock context."""
    _lib.hexlock_free(ctx)


def process(ctx: ctypes.c_void_p, text: str):
    """
    Scan text for PII and transform it.
    Returns (output_str, list of TokenRecord).
    """
    encoded = text.encode("utf-8")
    result_ptr = ctypes.POINTER(Result)()
    _check(_lib.hexlock_process(
        ctx,
        encoded,
        len(encoded),
        ctypes.byref(result_ptr),
    ))
    
    result = result_ptr.contents
    output = result.output.decode("utf-8")

    # Copy all fields into plain Python dicts BEFORE freeing C memory.
    # result.records[i] returns a ctypes view into the C heap — not an
    # independent copy — so reading .transformed/.original after
    # hexlock_result_free() would be a use-after-free.
    records = []
    for i in range(result.count):
        r = result.records[i]
        records.append({
            "type":        r.type,
            "algo":        r.algo,
            "subtype":     r.subtype,
            "token_key":   r.token_key,
            "transformed": bytes(r.transformed),
            "original":    bytes(r.original),
        })

    _lib.hexlock_result_free(result_ptr)
    return output, records


def decrypt(ctx: ctypes.c_void_p, transformed: str,
            pii_type: int, subtype: int) -> str:
    """Decrypt a single FPE-encrypted value."""
    encoded = transformed.encode("utf-8")
    buf = ctypes.create_string_buffer(encoded)
    _check(_lib.hexlock_decrypt(
        ctx,
        buf,
        len(encoded),
        pii_type,
        subtype,
    ))
    return buf.value.decode("utf-8")
