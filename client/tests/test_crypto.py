import base64

import pytest
from cryptography.exceptions import InvalidTag

from datavalv_client._format_constants import HEADER_LENGTH, IV_LENGTH, TAG_LENGTH
from datavalv_client.crypto import (
    decrypt,
    decrypt_with_tenant_key,
    encrypt,
    encrypt_to_tenant_key,
    generate_dek,
    generate_keypair,
    load_private_key_pem,
    load_public_key_pem,
    private_key_to_pem,
    public_key_to_pem,
    unwrap_dek,
    wrap_dek,
)
from datavalv_client.format import FormatError

PLAINTEXT = b"a club's backup archive" * 100


@pytest.fixture(scope="module")
def keypair():
    return generate_keypair()


def test_dek_is_256_bits():
    assert len(generate_dek()) == 32


def test_round_trip_recovers_the_plaintext():
    dek = generate_dek()
    assert decrypt(encrypt(PLAINTEXT, dek), dek) == PLAINTEXT


def test_ciphertext_length_is_plaintext_plus_header_and_tag():
    dek = generate_dek()
    assert len(encrypt(PLAINTEXT, dek)) == HEADER_LENGTH + len(PLAINTEXT) + TAG_LENGTH


def test_encrypting_twice_produces_different_ciphertext():
    """A fresh random IV each time, so identical backups are not identifiable."""
    dek = generate_dek()
    assert encrypt(PLAINTEXT, dek) != encrypt(PLAINTEXT, dek)


def test_explicit_iv_is_used_verbatim():
    iv = bytes(range(IV_LENGTH))
    assert encrypt(PLAINTEXT, generate_dek(), iv=iv)[9:HEADER_LENGTH] == iv


def test_wrong_key_fails_to_decrypt():
    blob = encrypt(PLAINTEXT, generate_dek())
    with pytest.raises(InvalidTag):
        decrypt(blob, generate_dek())


def test_tampering_with_the_body_is_detected():
    dek = generate_dek()
    blob = bytearray(encrypt(PLAINTEXT, dek))
    blob[HEADER_LENGTH] ^= 0x01
    with pytest.raises(InvalidTag):
        decrypt(bytes(blob), dek)


def test_altering_the_iv_in_the_header_is_detected():
    """The header is GCM additional authenticated data: altering the IV inside it
    must fail authentication rather than silently decrypt to rubbish."""
    dek = generate_dek()
    blob = bytearray(encrypt(PLAINTEXT, dek))
    blob[9] ^= 0xFF
    with pytest.raises(InvalidTag):
        decrypt(bytes(blob), dek)


def test_truncated_tag_is_rejected():
    dek = generate_dek()
    blob = encrypt(PLAINTEXT, dek)
    with pytest.raises(InvalidTag):
        decrypt(blob[:-1], dek)


def test_unknown_version_is_rejected_before_decryption():
    dek = generate_dek()
    blob = bytearray(encrypt(PLAINTEXT, dek))
    blob[4] = 2
    with pytest.raises(FormatError, match="version"):
        decrypt(bytes(blob), dek)


def test_dek_wrap_round_trip(keypair):
    dek = generate_dek()
    wrapped = wrap_dek(dek, keypair.public_key())
    assert wrapped != dek
    assert unwrap_dek(wrapped, keypair) == dek


def test_wrapping_is_randomised(keypair):
    """OAEP is randomised, so the same DEK wraps to different bytes each time."""
    dek = generate_dek()
    assert wrap_dek(dek, keypair.public_key()) != wrap_dek(dek, keypair.public_key())


def test_pem_round_trip(keypair):
    pub = load_public_key_pem(public_key_to_pem(keypair.public_key()))
    priv = load_private_key_pem(private_key_to_pem(keypair))
    dek = generate_dek()
    assert unwrap_dek(wrap_dek(dek, pub), priv) == dek


# --- short strings encrypted straight to a tenant key ---------------------
#
# Addresses, in practice: the half of the at-rest design that has to be shown
# to a member rather than compared, so it is encrypted rather than digested.
#
# Non-ASCII written as escapes and never typed. An editor recomposes what you
# type on save, and `DECOMPOSED_EMAIL` would then be the same bytes as
# `EMAIL` -- leaving the round trip below comparing a string to itself.
EMAIL = "m\u00e5ns@brommas\u00e5.se"
DECOMPOSED_EMAIL = "ma\u030ans@brommasa\u030a.se"


@pytest.mark.parametrize("text", [EMAIL, DECOMPOSED_EMAIL, "\u4e2d\u6587@example.cn", "a@b.se"])
def test_tenant_key_text_round_trip(keypair, text):
    cipher_b64 = encrypt_to_tenant_key(text, keypair.public_key())
    assert decrypt_with_tenant_key(cipher_b64, keypair) == text


def test_the_two_spellings_are_two_different_strings():
    """Guards the parametrisation above: recompose the decomposed case and it
    becomes a duplicate of the composed one, testing nothing twice."""
    assert EMAIL != DECOMPOSED_EMAIL


def test_the_ciphertext_does_not_contain_the_address(keypair):
    """The point of encrypting it. Base64 of anything is not the address, but a
    primitive that returned its input unchanged would satisfy the round trip
    above and this is the assertion that would not let it."""
    cipher_b64 = encrypt_to_tenant_key(EMAIL, keypair.public_key())
    assert EMAIL not in cipher_b64
    assert EMAIL.encode() not in base64.b64decode(cipher_b64)


def test_encrypting_one_address_twice_gives_different_ciphertext(keypair):
    """OAEP is randomised, and that is why it is the right vehicle here: two
    rows carrying one address must not be equal by inspection. If they were,
    the operator could tell which members share an address without any key."""
    first = encrypt_to_tenant_key(EMAIL, keypair.public_key())
    second = encrypt_to_tenant_key(EMAIL, keypair.public_key())
    assert first != second
    assert decrypt_with_tenant_key(first, keypair) == decrypt_with_tenant_key(second, keypair)


def test_a_wrong_tenant_key_fails_rather_than_returning_nonsense(keypair):
    """The failure has to be loud. An address that came back as rubbish would
    be rendered as rubbish in a member list rather than reported."""
    cipher_b64 = encrypt_to_tenant_key(EMAIL, keypair.public_key())
    with pytest.raises(ValueError):
        decrypt_with_tenant_key(cipher_b64, generate_keypair())


def test_it_does_not_normalise_what_it_is_given(keypair):
    """Deliberately not `normalise_email`'s job. This is the spelling a member
    will be shown, so lowercasing it here would display an address they never
    typed -- and the comparison the server does is the keyed HMAC, not this."""
    typed = "M\u00e5ns@Brommass.SE"
    cipher_b64 = encrypt_to_tenant_key(typed, keypair.public_key())
    assert decrypt_with_tenant_key(cipher_b64, keypair) == typed
