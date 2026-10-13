"""Datavalv ciphertext header encoding and decoding.

Pure byte manipulation, no cryptography. This module decides what Datavalv
refuses to read, so every rejection path is tested explicitly.
"""

from ._format_constants import (
    ALG_ID,
    HEADER_LENGTH,
    IV_LENGTH,
    MAGIC,
    RESERVED,
    VERSION,
)


class FormatError(ValueError):
    """The bytes are not a valid Datavalv v1 ciphertext header."""


def encode_header(iv: bytes) -> bytes:
    if len(iv) != IV_LENGTH:
        raise FormatError(f"iv length must be {IV_LENGTH}, got {len(iv)}")
    return MAGIC + bytes([VERSION, ALG_ID]) + RESERVED + bytes([IV_LENGTH]) + iv


def decode_header(blob: bytes) -> bytes:
    """Validate the header at the start of *blob* and return its IV."""
    if len(blob) < HEADER_LENGTH:
        raise FormatError(f"truncated header: need {HEADER_LENGTH} bytes, got {len(blob)}")
    if blob[0:4] != MAGIC:
        raise FormatError("bad magic: not a Datavalv ciphertext")
    if blob[4] != VERSION:
        raise FormatError(f"unsupported version {blob[4]}")
    if blob[5] != ALG_ID:
        raise FormatError(f"unsupported algorithm {blob[5]}")
    if blob[6:8] != RESERVED:
        raise FormatError("reserved bytes must be zero")
    if blob[8] != IV_LENGTH:
        raise FormatError(f"iv length must be {IV_LENGTH}, got {blob[8]}")
    return blob[9:HEADER_LENGTH]
