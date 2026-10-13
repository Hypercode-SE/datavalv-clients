import base64
import json
import os
import pathlib
import subprocess
import sys

from datavalv_client.crypto import generate_keypair, private_key_to_pem, public_key_to_pem

PLAINTEXT = b"conformance payload"
DEK = bytes(range(32))
IV = bytes(range(12))


SRC = pathlib.Path(__file__).resolve().parents[1] / "src"


def run(mode: str, job: dict) -> tuple[dict, int]:
    """Run the CLI as a real subprocess.

    pytest's ``pythonpath`` setting applies to the test process only, so the
    child needs PYTHONPATH explicitly or it cannot import the package.
    """
    proc = subprocess.run(
        [sys.executable, "-m", "datavalv_client.conformance", mode],
        input=json.dumps(job),
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONPATH": str(SRC)},
        check=False,  # a non-zero exit is the thing under test
    )
    assert proc.returncode != 1, proc.stderr
    return json.loads(proc.stdout), proc.returncode


def test_encrypt_then_decrypt_through_the_cli():
    key = generate_keypair()
    enc, code = run(
        "encrypt",
        {
            "plaintextB64": base64.b64encode(PLAINTEXT).decode(),
            "dekB64": base64.b64encode(DEK).decode(),
            "ivB64": base64.b64encode(IV).decode(),
            "publicKeyPem": public_key_to_pem(key.public_key()),
        },
    )
    assert code == 0

    dec, code = run(
        "decrypt",
        {
            "ciphertextB64": enc["ciphertextB64"],
            "wrappedDekB64": enc["wrappedDekB64"],
            "privateKeyPem": private_key_to_pem(key),
        },
    )
    assert code == 0
    assert base64.b64decode(dec["plaintextB64"]) == PLAINTEXT


def test_rejected_ciphertext_reports_an_error_without_crashing():
    key = generate_keypair()
    enc, _ = run(
        "encrypt",
        {
            "plaintextB64": base64.b64encode(PLAINTEXT).decode(),
            "dekB64": base64.b64encode(DEK).decode(),
            "ivB64": base64.b64encode(IV).decode(),
            "publicKeyPem": public_key_to_pem(key.public_key()),
        },
    )
    corrupt = bytearray(base64.b64decode(enc["ciphertextB64"]))
    corrupt[4] = 2  # unknown version

    dec, code = run(
        "decrypt",
        {
            "ciphertextB64": base64.b64encode(bytes(corrupt)).decode(),
            "wrappedDekB64": enc["wrappedDekB64"],
            "privateKeyPem": private_key_to_pem(key),
        },
    )
    assert code == 0
    assert "version" in dec["error"]
    assert "plaintextB64" not in dec
