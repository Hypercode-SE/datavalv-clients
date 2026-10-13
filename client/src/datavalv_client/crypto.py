"""Datavalv v1 content encryption.

AES-256-GCM for the payload with the 21-byte header as additional authenticated
data, and RSA-OAEP/SHA-256 with an empty label for wrapping the data key.

The OAEP label is deliberately empty. Non-empty labels have uneven support
across browser WebCrypto engines, and the browser is the only decryptor; domain
separation is structural instead, because DEKs are wrapped with a tenant key and
tenant keys with a member key.
"""

import base64
import hashlib
import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from ._format_constants import (
    AES_KEY_BITS,
    HEADER_LENGTH,
    HKDF_INFO,
    IV_LENGTH,
    RSA_MODULUS_BITS,
)
from .format import decode_header, encode_header

_OAEP = padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None,  # empty label; see module docstring
)


def generate_dek() -> bytes:
    return os.urandom(AES_KEY_BITS // 8)


def encrypt(plaintext: bytes, dek: bytes, iv: bytes | None = None) -> bytes:
    """Return a complete v1 ciphertext: header + ciphertext + tag."""
    iv = os.urandom(IV_LENGTH) if iv is None else iv
    header = encode_header(iv)
    return header + AESGCM(dek).encrypt(iv, plaintext, header)


def decrypt(blob: bytes, dek: bytes) -> bytes:
    """Validate the header, then authenticate and decrypt the payload."""
    iv = decode_header(blob)
    header = blob[:HEADER_LENGTH]
    return AESGCM(dek).decrypt(iv, blob[HEADER_LENGTH:], header)


def wrap_dek(dek: bytes, public_key: RSAPublicKey) -> bytes:
    return public_key.encrypt(dek, _OAEP)


def unwrap_dek(wrapped: bytes, private_key: RSAPrivateKey) -> bytes:
    return private_key.decrypt(wrapped, _OAEP)


def encrypt_to_tenant_key(text: str, public_key: RSAPublicKey) -> str:
    """Encrypt a short string straight to a tenant's public key. Base64 out.

    For the values that have to be *shown* to a member rather than compared --
    email addresses, today. They ride under the tenant key directly rather than
    under a DEK the way a filename does, because a filename has a backup to
    belong to and an address has none.

    ``_OAEP`` above, the same object ``wrap_dek`` passes: RSA-OAEP with SHA-256
    and the empty label. A second set of OAEP arguments written beside the first
    is two things that can drift, and the drift would not show up until a
    browser could not read what Python wrote.

    Randomised, because OAEP is. Two rows carrying one address must not be equal
    by inspection; testing equality is the HMAC's job and the HMAC is keyed.

    Does **not** normalise. What goes in comes back out byte for byte, because
    this is the spelling a member will be shown. `emails.normalise_email` is for
    the digest that gets compared, and conflating the two would mean displaying
    a lowercased address the member never typed.

    RSA-3072-OAEP/SHA-256 takes at most 318 bytes; ``cryptography`` refuses
    anything longer rather than truncating.
    """
    return base64.b64encode(public_key.encrypt(text.encode("utf-8"), _OAEP)).decode()


def decrypt_with_tenant_key(cipher_b64: str, private_key: RSAPrivateKey) -> str:
    """The other half of `encrypt_to_tenant_key`. Raises on the wrong key."""
    return private_key.decrypt(base64.b64decode(cipher_b64), _OAEP).decode("utf-8")


def generate_keypair() -> RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=RSA_MODULUS_BITS)


def load_public_key_pem(pem: str | bytes) -> RSAPublicKey:
    data = pem.encode() if isinstance(pem, str) else pem
    key = serialization.load_pem_public_key(data)
    if not isinstance(key, RSAPublicKey):
        raise TypeError("expected an RSA public key")
    return key


def public_key_fingerprint(pem: str | bytes) -> str:
    """SHA-256 over the key's SubjectPublicKeyInfo DER, as 64 lowercase hex.

    The definition the whole project shares (`crypto/src/crypto.ts`, design
    section 6.1.1), chosen so that a person needs nothing of ours to compute
    it:

        openssl pkey -pubin -outform DER | openssl dgst -sha256

    Over the DER and never the PEM text -- line endings and wrapping differ
    between tools that agree about the key -- and through a parse, so that a
    private key or a truncated paste is refused rather than given a fingerprint
    nothing else will ever match. That would read as "the key was substituted",
    which is the one alarm this must not raise falsely.
    """
    data = pem.encode() if isinstance(pem, str) else pem
    key = load_public_key_pem(data.strip())
    der = key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return hashlib.sha256(der).hexdigest()


def load_private_key_pem(pem: str | bytes) -> RSAPrivateKey:
    data = pem.encode() if isinstance(pem, str) else pem
    key = serialization.load_pem_private_key(data, password=None)
    if not isinstance(key, RSAPrivateKey):
        raise TypeError("expected an RSA private key")
    return key


def public_key_to_pem(key: RSAPublicKey) -> str:
    return key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()


def private_key_to_pem(key: RSAPrivateKey) -> str:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()


def hkdf(ikm: bytes, info: str, length_bytes: int = 32) -> bytes:
    """HKDF-SHA256 with an empty salt.

    The counterpart of ``hkdf`` in ``crypto/src/derive.ts``, down to the empty
    salt. An empty HMAC key and a key of ``digest_size`` zero bytes are the
    same key once HMAC pads it to the block size, so this matches WebCrypto's
    ``salt: new Uint8Array(0)`` byte for byte -- which is what the conformance
    matrix checks rather than assumes.

    ``ikm`` is always something that is already full-entropy: an Argon2id
    master key, a recovery code, an invite secret. Never a password; HKDF is
    fast by design and offers no brute-force resistance.
    """
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length_bytes,
        salt=b"",
        info=info.encode(),
    ).derive(ikm)


def derive_invite_key(secret: bytes) -> bytes:
    """The key an invite's tenant-key wrapping is done under.

    Derived from the 256-bit invite secret rather than being it. The secret
    rides in a URL fragment -- never sent to a server, but present in the
    invitee's address bar and history -- so the value that opens the vault sits
    one HKDF step away from the value that travels.
    """
    return hkdf(secret, HKDF_INFO["invite"], AES_KEY_BITS // 8)
