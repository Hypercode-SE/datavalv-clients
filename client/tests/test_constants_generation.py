import json
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]


def test_generated_python_constants_match_source_of_truth():
    from datavalv_client import _format_constants as c

    spec = json.loads((ROOT / "format" / "v1.json").read_text())
    assert c.MAGIC == spec["magic"].encode("ascii")
    assert c.VERSION == spec["version"]
    assert c.ALG_ID == spec["algId"]
    assert c.IV_LENGTH == spec["ivLength"]
    assert c.TAG_LENGTH == spec["tagLength"]
    assert c.HEADER_LENGTH == spec["headerLength"]
    assert c.RSA_MODULUS_BITS == spec["rsa"]["modulusBits"]
    assert c.HKDF_INFO == spec["hkdf"]["info"]
    assert c.LOGIN_HASH_PREFIX == spec["loginHashPrefix"]


def test_header_length_is_consistent_with_its_parts():
    spec = json.loads((ROOT / "format" / "v1.json").read_text())
    # magic(4) + version(1) + algId(1) + reserved(2) + ivLen(1) + iv
    assert spec["headerLength"] == 4 + 1 + 1 + 2 + 1 + spec["ivLength"]


def test_generator_is_idempotent():
    """Regenerating must not change the committed files. CI relies on this."""
    before = (ROOT / "client/src/datavalv_client/_format_constants.py").read_bytes()
    subprocess.run([sys.executable, str(ROOT / "scripts/gen_constants.py")], check=True)
    after = (ROOT / "client/src/datavalv_client/_format_constants.py").read_bytes()
    assert before == after
