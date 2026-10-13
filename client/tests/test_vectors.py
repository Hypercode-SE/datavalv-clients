import base64
import json
import pathlib

import pytest

from datavalv_client.crypto import decrypt, encrypt, load_private_key_pem, unwrap_dek

VECTORS = json.loads(
    (pathlib.Path(__file__).resolve().parents[2] / "format/vectors/v1/vectors.json").read_text()
)
CASES = [pytest.param(c, id=c["name"]) for c in VECTORS["cases"]]


def b64(text: str) -> bytes:
    return base64.b64decode(text)


@pytest.mark.parametrize("case", CASES)
def test_ciphertext_matches_the_vector_byte_for_byte(case):
    """Fixed IV, so the output is deterministic and pins the format."""
    produced = encrypt(b64(case["plaintextB64"]), b64(case["dekB64"]), iv=b64(case["ivB64"]))
    assert produced == b64(case["ciphertextB64"])


@pytest.mark.parametrize("case", CASES)
def test_vector_ciphertext_decrypts_to_the_vector_plaintext(case):
    assert decrypt(b64(case["ciphertextB64"]), b64(case["dekB64"])) == b64(case["plaintextB64"])


@pytest.mark.parametrize("case", CASES)
def test_vector_wrapped_dek_unwraps(case):
    private_key = load_private_key_pem(VECTORS["privateKeyPem"])
    assert unwrap_dek(b64(case["wrappedDekB64"]), private_key) == b64(case["dekB64"])
