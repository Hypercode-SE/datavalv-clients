"""The key a backup is encrypted to, and whose word it is taken on.

Step 1 of a push asks the service for the vault's public key, and the service is
the one party this design does not trust with plaintext: a server that answered
with a key of its own would read every backup from then on, and nothing in the
protocol could show it. So the client remembers the fingerprint of the key it
was first given for each vault, and refuses -- before encrypting anything -- if
a later answer is a different key. A vault's key never changes.
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import httpx
import pytest
from conftest import API_BASE, CLIENT_ID, EXTERNAL_ID, KEY_ID, FakeDatavalv

from datavalv_client import DatavalvClient, FilePins, MemoryPins, VaultKeyChanged, crypto

PLAINTEXT = b"medlemsregister"

#: `publicKeyPem` from `format/vectors/v1/vectors.json`, through
#: `openssl pkey -pubin -outform DER | openssl dgst -sha256`. Produced by none
#: of this project's code, and the same constant `crypto/tests/fingerprint.test.ts`
#: holds -- which is what makes the two implementations agree with each other
#: and with a person at a shell.
VECTORS = json.loads(
    (Path(__file__).resolve().parents[2] / "format" / "vectors" / "v1" / "vectors.json").read_text()
)
OPENSSL_SAYS = "de6272b8151979389437054b06df8a817a6ad62ab87faac4bbacb3360c1385d0"


def _client(service: FakeDatavalv, signing_key_pem: str, **kwargs) -> DatavalvClient:
    return DatavalvClient(
        API_BASE,
        CLIENT_ID,
        KEY_ID,
        signing_key_pem,
        transport=httpx.MockTransport(service),
        **kwargs,
    )


# ------------------------------------------------------------- the fingerprint


def test_the_fingerprint_agrees_with_openssl():
    assert crypto.public_key_fingerprint(VECTORS["publicKeyPem"]) == OPENSSL_SAYS


def test_the_fingerprint_is_of_the_key_and_not_of_how_its_pem_is_laid_out():
    pem = VECTORS["publicKeyPem"]
    body = "".join(line for line in pem.splitlines() if "-----" not in line)
    relaid = [
        pem.replace("\n", "\r\n"),
        f"-----BEGIN PUBLIC KEY-----\n{body}\n-----END PUBLIC KEY-----",
        f"  {pem}  \n\n",
    ]
    assert {crypto.public_key_fingerprint(one) for one in relaid} == {OPENSSL_SAYS}


def test_a_private_key_is_refused_rather_than_fingerprinted():
    """Both are PEM and both would hash. A fingerprint of the wrong thing
    matches nothing anybody else computes, and reads as a substituted key."""
    with pytest.raises((TypeError, ValueError)):
        crypto.public_key_fingerprint(VECTORS["privateKeyPem"])


# --------------------------------------------------------------- pinning


def test_the_first_push_records_the_key_and_says_so(service, signing_key_pem, tenant_public_pem):
    pins = MemoryPins()
    with _client(service, signing_key_pem, pins=pins) as client:
        pushed = client.push_backup(EXTERNAL_ID, PLAINTEXT)

    expected = crypto.public_key_fingerprint(tenant_public_pem)
    assert pushed.key_fingerprint == expected
    assert pushed.key_first_seen is True
    assert pins.get(API_BASE, CLIENT_ID, EXTERNAL_ID) == expected


def test_a_later_push_to_the_same_key_is_not_a_first_sighting(service, signing_key_pem):
    pins = MemoryPins()
    with _client(service, signing_key_pem, pins=pins) as client:
        client.push_backup(EXTERNAL_ID, PLAINTEXT)
        again = client.push_backup(EXTERNAL_ID, PLAINTEXT)

    assert again.key_first_seen is False


def test_a_different_key_is_refused_before_anything_is_encrypted_or_sent(
    service, signing_key_pem, tenant_public_pem
):
    """**The attack, from the client's side.** The service answers step 1 with a
    key that is not the one this server has seen for this vault. Whatever the
    reason, encrypting to it is the one thing that must not happen, so the push
    stops after that single GET: no copy registered, nothing uploaded."""
    pins = MemoryPins()
    with _client(service, signing_key_pem, pins=pins) as client:
        client.push_backup(EXTERNAL_ID, PLAINTEXT)

    substituted = crypto.public_key_to_pem(crypto.generate_keypair().public_key())
    service.tenant_public_pem = substituted
    service.calls.clear()
    service.uploaded = None

    with (
        _client(service, signing_key_pem, pins=pins) as client,
        pytest.raises(VaultKeyChanged) as raised,
    ):
        client.push_backup(EXTERNAL_ID, PLAINTEXT)

    assert [call.step for call in service.calls] == [f"GET /v1/tenants/{EXTERNAL_ID}/public-key"]
    assert service.uploaded is None
    error = raised.value
    assert error.retryable is False
    assert error.pinned == crypto.public_key_fingerprint(tenant_public_pem)
    assert error.offered == crypto.public_key_fingerprint(substituted)
    # Both fingerprints, and the vault: what a person needs to go and compare.
    assert error.pinned in str(error) and error.offered in str(error)
    assert EXTERNAL_ID in str(error)
    # The pin is not moved by a refusal. A client that re-pinned on mismatch
    # would refuse once and then comply.
    assert pins.get(API_BASE, CLIENT_ID, EXTERNAL_ID) == error.pinned


def test_a_pin_belongs_to_one_vault_of_one_application_on_one_api(service, signing_key_pem):
    """`kund-4711` on staging and `kund-4711` on production are different vaults
    with different keys, and so is another application's `kund-4711`."""
    pins = MemoryPins()
    pins.set(API_BASE, CLIENT_ID, "another-vault", "0" * 64)
    pins.set("https://api.datavalv.se", CLIENT_ID, EXTERNAL_ID, "1" * 64)
    pins.set(API_BASE, "another-client", EXTERNAL_ID, "2" * 64)

    with _client(service, signing_key_pem, pins=pins) as client:
        pushed = client.push_backup(EXTERNAL_ID, PLAINTEXT)

    assert pushed.key_first_seen is True


def test_pins_can_be_given_in_advance_for_a_machine_with_no_disk_to_remember_on(
    service, signing_key_pem, tenant_public_pem
):
    """A container that starts empty every night sees every key for the first
    time, which is no protection at all. Its operator compares the fingerprint
    once and puts it in configuration; a vault whose key is not that one is
    then refused from the first push."""
    expected = crypto.public_key_fingerprint(tenant_public_pem)
    right = MemoryPins({(API_BASE, CLIENT_ID, EXTERNAL_ID): expected})
    wrong = MemoryPins({(API_BASE, CLIENT_ID, EXTERNAL_ID): "f" * 64})

    with _client(service, signing_key_pem, pins=right) as client:
        assert client.push_backup(EXTERNAL_ID, PLAINTEXT).key_first_seen is False
    with _client(service, signing_key_pem, pins=wrong) as client, pytest.raises(VaultKeyChanged):
        client.push_backup(EXTERNAL_ID, PLAINTEXT)


# -------------------------------------------------------------- the pin file


def test_pins_are_remembered_on_disk_by_default(service, signing_key_pem, tmp_path):
    """The default is a file, as `known_hosts` is: a second *process* has to
    refuse a changed key, and that is every scheduled push after the first."""
    with _client(service, signing_key_pem) as client:
        first = client.push_backup(EXTERNAL_ID, PLAINTEXT)
    with _client(service, signing_key_pem) as client:
        second = client.push_backup(EXTERNAL_ID, PLAINTEXT)

    assert (first.key_first_seen, second.key_first_seen) == (True, False)
    assert Path(os.environ["DATAVALV_KNOWN_VAULTS"]).is_file()


def test_the_pin_file_survives_a_new_process_and_refuses_a_changed_key(
    service, signing_key_pem, tmp_path
):
    path = tmp_path / "pins.json"
    with _client(service, signing_key_pem, pins=FilePins(path)) as client:
        client.push_backup(EXTERNAL_ID, PLAINTEXT)

    service.tenant_public_pem = crypto.public_key_to_pem(crypto.generate_keypair().public_key())
    with (
        _client(service, signing_key_pem, pins=FilePins(path)) as client,
        pytest.raises(VaultKeyChanged),
    ):
        client.push_backup(EXTERNAL_ID, PLAINTEXT)


def test_the_pin_file_is_private_and_its_directory_is_made(tmp_path):
    path = tmp_path / "state" / "datavalv" / "known_vaults.json"
    FilePins(path).set(API_BASE, CLIENT_ID, EXTERNAL_ID, "a" * 64)

    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700


def test_the_pin_file_is_the_same_file_the_typescript_client_writes(tmp_path):
    """One machine may run either client, or both. The format is stated here
    and in `client-ts/tests/pins.test.ts`, character for character."""
    path = tmp_path / "pins.json"
    FilePins(path).set(API_BASE, CLIENT_ID, EXTERNAL_ID, "a" * 64)

    assert json.loads(path.read_text()) == {
        "version": 1,
        "vaults": {f"{API_BASE} {CLIENT_ID} {EXTERNAL_ID}": {"fingerprint": "a" * 64}},
    }


def test_a_pin_file_that_cannot_be_read_as_one_stops_the_push(service, signing_key_pem, tmp_path):
    """Treating a corrupt file as an empty one would turn "somebody damaged the
    pin file" into "every key is new, carry on" -- which is the attack with one
    extra step. It is a configuration error and a person looks at it."""
    from datavalv_client import ConfigurationError

    path = tmp_path / "pins.json"
    path.write_text("{ not json")
    with (
        _client(service, signing_key_pem, pins=FilePins(path)) as client,
        pytest.raises(ConfigurationError),
    ):
        client.push_backup(EXTERNAL_ID, PLAINTEXT)
    assert service.uploaded is None


def test_a_pin_can_be_forgotten_after_a_person_has_checked_why_it_changed(tmp_path):
    """A vault deleted and created again is a new vault with a new key. That is
    the one honest reason for a change, and it takes a person to know it."""
    pins = FilePins(tmp_path / "pins.json")
    pins.set(API_BASE, CLIENT_ID, EXTERNAL_ID, "a" * 64)
    pins.forget(API_BASE, CLIENT_ID, EXTERNAL_ID)
    assert pins.get(API_BASE, CLIENT_ID, EXTERNAL_ID) is None
