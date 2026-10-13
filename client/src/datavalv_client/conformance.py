"""Conformance CLI: one JSON job on stdin, one JSON result on stdout.

The TypeScript implementation exposes an identical contract, so CI can pipe
between the two and prove they agree on live code rather than stored fixtures.

A rejected ciphertext is a RESULT, reported as {"error": ...} with exit code 0.
Exit code 2 means the job itself was malformed.
"""

import base64
import json
import sys

from .crypto import (
    decrypt,
    decrypt_with_tenant_key,
    derive_invite_key,
    encrypt,
    encrypt_to_tenant_key,
    load_private_key_pem,
    load_public_key_pem,
    unwrap_dek,
    wrap_dek,
)

MODES = {"encrypt", "decrypt", "invite-key", "encrypt-text", "decrypt-text"}


def _b64d(text: str) -> bytes:
    return base64.b64decode(text)


def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode()


def _encrypt(job: dict) -> dict:
    dek = _b64d(job["dekB64"])
    blob = encrypt(_b64d(job["plaintextB64"]), dek, iv=_b64d(job["ivB64"]))
    wrapped = wrap_dek(dek, load_public_key_pem(job["publicKeyPem"]))
    return {"ciphertextB64": _b64e(blob), "wrappedDekB64": _b64e(wrapped)}


def _decrypt(job: dict) -> dict:
    try:
        private_key = load_private_key_pem(job["privateKeyPem"])
        dek = unwrap_dek(_b64d(job["wrappedDekB64"]), private_key)
        return {"plaintextB64": _b64e(decrypt(_b64d(job["ciphertextB64"]), dek))}
    except Exception as exc:  # noqa: BLE001 - rejection is the result we report
        return {"error": f"{type(exc).__name__}: {exc}"}


def _encrypt_text(job: dict) -> dict:
    """A short string encrypted straight to a tenant key -- an address, in practice.

    Text in and text out rather than base64 in and base64 out: the defect this
    crossing exists to catch is a UTF-8 one, and comparing base64 would let a
    mangled code point through as long as both sides mangled it the same way.
    """
    public_key = load_public_key_pem(job["publicKeyPem"])
    return {"cipherB64": encrypt_to_tenant_key(job["text"], public_key)}


def _decrypt_text(job: dict) -> dict:
    try:
        private_key = load_private_key_pem(job["privateKeyPem"])
        return {"text": decrypt_with_tenant_key(job["cipherB64"], private_key)}
    except Exception as exc:  # noqa: BLE001 - rejection is the result we report
        return {"error": f"{type(exc).__name__}: {exc}"}


def _invite_key(job: dict) -> dict:
    """Hex in, hex out: the invite vectors are hex, and stay hex end to end."""
    return {"inviteKeyHex": derive_invite_key(bytes.fromhex(job["secretHex"])).hex()}


def main() -> int:
    if len(sys.argv) != 2 or sys.argv[1] not in MODES:
        print(
            "usage: python -m datavalv_client.conformance " + "|".join(sorted(MODES)),
            file=sys.stderr,
        )
        return 2
    try:
        job = json.loads(sys.stdin.read())
    except json.JSONDecodeError as exc:
        print(f"malformed job: {exc}", file=sys.stderr)
        return 2

    handlers = {
        "encrypt": _encrypt,
        "decrypt": _decrypt,
        "invite-key": _invite_key,
        "encrypt-text": _encrypt_text,
        "decrypt-text": _decrypt_text,
    }
    json.dump(handlers[sys.argv[1]](job), sys.stdout)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
