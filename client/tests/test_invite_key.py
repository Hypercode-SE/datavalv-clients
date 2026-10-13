"""The Python half of the invite-key derivation.

`crypto/tests/invite.test.ts` reads the same vector file and
`scripts/conformance_matrix.py` pipes it through both conformance CLIs, so a
derivation that drifted in one language and not the other cannot merge.
"""

import json
import pathlib

import pytest

from datavalv_client._format_constants import HKDF_INFO
from datavalv_client.crypto import derive_invite_key, hkdf

VECTOR_PATH = pathlib.Path(__file__).resolve().parents[2] / "format/vectors/v1/invite-key.json"
VECTORS = json.loads(VECTOR_PATH.read_text())
CASES = [pytest.param(c, id=c["name"]) for c in VECTORS["cases"]]

SECRET = bytes(32)  # any fixed 256-bit secret; the tests below vary only the info


def test_the_vector_file_describes_the_derivation_this_module_performs():
    assert VECTORS["info"] == HKDF_INFO["invite"]
    assert VECTORS["lengthBytes"] == 32
    assert len(VECTORS["cases"]) >= 3


@pytest.mark.parametrize("case", CASES)
def test_invite_key_reproduces_the_pinned_vector(case):
    secret = bytes.fromhex(case["secretHex"])
    assert len(secret) == 32
    assert derive_invite_key(secret).hex() == case["inviteKeyHex"]


def test_invite_key_is_thirty_two_bytes_and_deterministic():
    once = derive_invite_key(SECRET)
    assert len(once) == 32
    assert once == derive_invite_key(SECRET)


def test_invite_key_is_not_the_secret_it_came_from():
    # The secret travels in a URL fragment; the key opens the vault. If they
    # were the same value, a fragment sitting in a browser history entry would
    # be the vault key rather than one step away from it.
    assert derive_invite_key(SECRET) != SECRET


@pytest.mark.parametrize("info", ["recovery", "kek", "login"])
def test_only_the_info_string_separates_the_invite_key(info):
    # Same HKDF, same input keying material, same output length: the only
    # thing standing between these two values is the info string, so dropping
    # or confusing the info is the only way to make this fail.
    assert derive_invite_key(SECRET) != hkdf(SECRET, HKDF_INFO[info], 32)


def test_an_empty_info_string_does_not_produce_the_invite_key():
    assert derive_invite_key(SECRET) != hkdf(SECRET, "", 32)
