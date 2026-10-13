import pytest

from datavalv_client._format_constants import HEADER_LENGTH, IV_LENGTH
from datavalv_client.format import FormatError, decode_header, encode_header

IV = bytes(range(IV_LENGTH))


def test_encoded_header_has_the_specified_layout():
    header = encode_header(IV)
    assert len(header) == HEADER_LENGTH
    assert header[0:4] == b"DVLV"
    assert header[4] == 1  # version
    assert header[5] == 1  # algId
    assert header[6:8] == b"\x00\x00"  # reserved
    assert header[8] == IV_LENGTH
    assert header[9:21] == IV


def test_decode_returns_the_iv_that_was_encoded():
    assert decode_header(encode_header(IV)) == IV


def test_decode_ignores_trailing_ciphertext():
    assert decode_header(encode_header(IV) + b"ciphertext bytes") == IV


def test_encode_rejects_wrong_iv_length():
    with pytest.raises(FormatError, match="iv length"):
        encode_header(b"short")


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda h: b"XVLV" + h[4:], "magic"),
        (lambda h: h[:4] + bytes([2]) + h[5:], "version"),
        (lambda h: h[:5] + bytes([9]) + h[6:], "algorithm"),
        (lambda h: h[:6] + b"\x00\x01" + h[8:], "reserved"),
        (lambda h: h[:8] + bytes([16]) + h[9:], "iv length"),
        (lambda h: h[:10], "truncated"),
    ],
)
def test_decode_rejects_malformed_headers(mutate, message):
    with pytest.raises(FormatError, match=message):
        decode_header(mutate(encode_header(IV)))
