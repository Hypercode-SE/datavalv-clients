"""The four calls, the three tokens, and the one digest.

Every assertion here was checked by breaking the code it covers and watching it
fail; where the break is not obvious from the assertion, the test says what it
was. That matters more than usual in this file: three of the things it checks —
the ordering, the token per call, and the two spellings of one digest — are
each satisfied by a plausible wrong implementation that a weaker assertion
passes.
"""

from __future__ import annotations

import base64
import hashlib
import io

import httpx
import jwt
import pytest
from conftest import (
    API_BASE,
    BACKUP_ID,
    CLIENT_ID,
    EXTERNAL_ID,
    KEY_ID,
    MAX_ISSUED_LIFETIME,
    TENANT_KEY_ID,
    UPLOAD_URL,
    FakeDatavalv,
)

from datavalv_client import crypto
from datavalv_client.client import DatavalvClient
from datavalv_client.errors import (
    ApiError,
    AuthError,
    ConfigurationError,
    NetworkError,
    QuotaExceeded,
    RequestInFlight,
    StorageFull,
    UploadError,
    VaultNotInitialized,
)
from datavalv_client.format import decode_header

PLAINTEXT = b"-- a database dump, or near enough\n" * 64

#: What the API really answers while a vault is waiting for its owner, detail
#: and all: `routes_backups.create_backup` raises `TenantNotInitialized` with
#: exactly this sentence.
DETAIL_409 = (
    b'{"code":"tenant_not_initialized","detail":"no member has generated the'
    b' tenant key yet; retry after first login"}'
)

#: The four steps, in the only order in which a backup exists at the end.
FOUR_CALLS = [
    f"GET /v1/tenants/{EXTERNAL_ID}/public-key",
    f"POST /v1/tenants/{EXTERNAL_ID}/backups",
    "PUT upload",
    f"POST /v1/backups/{BACKUP_ID}/complete",
]


def make_client(service: FakeDatavalv, signing_key_pem: str, **kwargs) -> DatavalvClient:
    return DatavalvClient(
        API_BASE,
        CLIENT_ID,
        KEY_ID,
        signing_key_pem,
        transport=httpx.MockTransport(service),
        **kwargs,
    )


# ------------------------------------------------------------------ ordering


def test_push_makes_the_four_calls_in_order(service, signing_key_pem):
    with make_client(service, signing_key_pem) as client:
        pushed = client.push_backup(EXTERNAL_ID, PLAINTEXT, name="dump.sql.gz")

    assert [call.step for call in service.calls] == FOUR_CALLS
    assert pushed.backup_id == BACKUP_ID
    assert pushed.sha256 == hashlib.sha256(service.uploaded).hexdigest()


@pytest.mark.parametrize("stop_after", [1, 2, 3, 4])
def test_a_failure_at_any_step_stops_the_ones_after_it(service, signing_key_pem, stop_after):
    """Break link *n* and check that links *n+1* onwards never ran.

    Asserting only that push_backup raised would pass for a client that made
    all four calls and reported the first failure at the end — which is the
    failure mode that leaves an object uploaded against a backup row that the
    caller was told had failed.
    """
    service.fail_at = FOUR_CALLS[stop_after - 1]
    service.failure = (500, b'{"code":"internal_error"}')

    with (
        make_client(service, signing_key_pem) as client,
        pytest.raises((ApiError, UploadError)),
    ):
        client.push_backup(EXTERNAL_ID, PLAINTEXT)

    assert [call.step for call in service.calls] == FOUR_CALLS[:stop_after]


def test_nothing_is_uploaded_when_registering_fails(service, signing_key_pem):
    service.fail_at = FOUR_CALLS[1]
    service.failure = (413, b'{"code":"too_large","detail":"exceeds the cap"}')

    with make_client(service, signing_key_pem) as client, pytest.raises(ApiError):
        client.push_backup(EXTERNAL_ID, PLAINTEXT)

    assert service.uploaded is None


# -------------------------------------------------------------------- tokens


def _tokens_of(service: FakeDatavalv) -> list[str]:
    return [call.token for call in service.calls if call.token is not None]


def test_each_datavalv_call_carries_its_own_token(service, signing_key_pem, signing_key):
    """Three calls, three tokens, three `jti`s — and each one verifies.

    The fake authorizer records `jti`s and refuses a repeat, exactly as the
    deployed one does, so hoisting the header into a variable turns this into a
    403 on the second call rather than a subtle assertion failure. Both halves
    are asserted anyway: a client could mint three tokens sharing one `jti`,
    which the uniqueness check catches and the 403 would too, and a client could
    mint three unverifiable tokens against a fake that did not check.
    """
    with make_client(service, signing_key_pem) as client:
        client.push_backup(EXTERNAL_ID, PLAINTEXT)

    tokens = _tokens_of(service)
    assert len(tokens) == 3, "the three Datavalv calls each need their own token"
    assert len(set(tokens)) == 3

    public_pem = crypto.public_key_to_pem(signing_key.public_key())
    jtis = set()
    for token in tokens:
        assert jwt.get_unverified_header(token)["kid"] == KEY_ID
        claims = jwt.decode(
            token,
            public_pem,
            algorithms=["RS256"],
            audience="datavalv",
            issuer=CLIENT_ID,
            options={"require": ["exp", "iat", "iss", "aud", "jti"]},
        )
        assert claims["exp"] - claims["iat"] <= MAX_ISSUED_LIFETIME
        jtis.add(claims["jti"])
    assert len(jtis) == 3, "a jti is recorded once; three calls need three of them"


def test_the_upload_carries_no_datavalv_token(service, signing_key_pem):
    """The presigned URL is its own authorisation, and S3 refuses a second one.

    The fake answers 400 InvalidArgument to an upload that carries an
    `Authorization` header, so adding one to `upload_ciphertext` fails this
    twice over.
    """
    with make_client(service, signing_key_pem) as client:
        client.push_backup(EXTERNAL_ID, PLAINTEXT)

    upload = next(call for call in service.calls if call.step == "PUT upload")
    assert upload.token is None
    assert "authorization" not in upload.headers


def test_a_replayed_token_is_refused(service, signing_key_pem, signing_key):
    """The single-use rule itself, stated directly rather than only implied.

    This is what a hoisted header would run into. It also proves the fake is
    capable of failing the test above, rather than passing it by not looking.
    """
    with make_client(service, signing_key_pem) as client:
        client.tenant_public_key(EXTERNAL_ID)
        replayed = service.calls[0].headers["authorization"]

    # The same token a second time, by hand.
    with httpx.Client(transport=httpx.MockTransport(service)) as raw:
        response = raw.get(
            f"{API_BASE}/v1/tenants/{EXTERNAL_ID}/public-key",
            headers={"Authorization": replayed},
        )
    assert response.status_code == 403


# ------------------------------------------------------------------- digests


def test_the_body_digest_and_the_upload_header_are_one_digest(service, signing_key_pem):
    """Hex in the body, base64 in the header, one value underneath.

    Asserted as one relation on purpose: `sha256 == sha256(blob).hexdigest()`
    alone passes while the header carries a different digest, and the header
    assertion alone passes while the body does. The service checks both against
    S3 at completion, so a client where they disagree fails at step 4 with a
    checksum mismatch and no indication which of the two was wrong.
    """
    with make_client(service, signing_key_pem) as client:
        client.push_backup(EXTERNAL_ID, PLAINTEXT)

    registered = next(call for call in service.calls if call.step == FOUR_CALLS[1]).json()
    upload = next(call for call in service.calls if call.step == "PUT upload")
    header_b64 = upload.headers["x-amz-checksum-sha256"]

    assert bytes.fromhex(registered["sha256"]) == base64.b64decode(header_b64)
    assert bytes.fromhex(registered["sha256"]) == hashlib.sha256(upload.content).digest()
    assert registered["size"] == len(upload.content)

    # `presigned_put` signs ContentLength as well as the checksum, so the
    # upload must state a length S3 can check against the signature. A body
    # sent as an iterator would go up chunked, with no Content-Length at all,
    # and S3 would answer 403 with nothing in it about why.
    assert int(upload.headers["content-length"]) == registered["size"]


def test_the_digest_is_the_ciphertexts_and_not_the_plaintexts(service, signing_key_pem):
    """The one substitution that looks right everywhere except at S3.

    The declared digest must be of the bytes that are uploaded. Hashing the
    plaintext is self-consistent in the request body and fails only when S3
    compares the signed checksum against what it actually received.
    """
    with make_client(service, signing_key_pem) as client:
        client.push_backup(EXTERNAL_ID, PLAINTEXT)

    registered = next(call for call in service.calls if call.step == FOUR_CALLS[1]).json()
    assert registered["sha256"] != hashlib.sha256(PLAINTEXT).hexdigest()
    assert registered["sha256"] == hashlib.sha256(service.uploaded).hexdigest()


def test_an_upload_without_the_checksum_header_is_refused(service):
    """`x-amz-checksum-sha256` is required by the signature, not merely accepted.

    Stated against the fake directly, the same way the replay test is: it is
    what makes dropping the header from `upload_ciphertext` a failing test
    rather than a silent change every other test here would pass.
    """
    with httpx.Client(transport=httpx.MockTransport(service)) as raw:
        without = raw.put(UPLOAD_URL, content=b"anything")
        assert without.status_code == 403

        digest = hashlib.sha256(b"anything").digest()
        with_header = raw.put(
            UPLOAD_URL,
            content=b"anything",
            headers={"x-amz-checksum-sha256": base64.b64encode(digest).decode()},
        )
        assert with_header.status_code == 200

        wrong = raw.put(
            UPLOAD_URL,
            content=b"something else",
            headers={"x-amz-checksum-sha256": base64.b64encode(digest).decode()},
        )
        assert wrong.status_code == 400


# ----------------------------------------------------------- the crypto round


def test_the_uploaded_ciphertext_opens_with_the_wrapped_dek(service, signing_key_pem, tenant_key):
    """The end-to-end property the whole protocol exists for.

    A member's browser holds the tenant private key, unwraps `wrappedDekB64`
    and decrypts what S3 stored. Standing in for that browser here is what
    proves the DEK sent is the DEK used — the two are separate values in
    `_push` and nothing else in this file would notice them diverging.
    """
    with make_client(service, signing_key_pem) as client:
        client.push_backup(EXTERNAL_ID, PLAINTEXT, name="dump.sql.gz")

    registered = next(call for call in service.calls if call.step == FOUR_CALLS[1]).json()
    assert registered["keyId"] == TENANT_KEY_ID

    dek = crypto.unwrap_dek(base64.b64decode(registered["wrappedDekB64"]), tenant_key)
    assert crypto.decrypt(service.uploaded, dek) == PLAINTEXT

    # `ivB64` is the payload's own IV, which is also inside the header the
    # ciphertext carries. A second, unrelated IV in that field would decrypt
    # here and still be wrong.
    assert base64.b64decode(registered["ivB64"]) == decode_header(service.uploaded)


def test_the_filename_is_encrypted_under_the_same_dek_with_its_own_iv(
    service, signing_key_pem, tenant_key
):
    """`nameCipherB64` opens with the backup's DEK — and reuses no nonce.

    Passing the payload's IV to the name's encryption would be catastrophic
    rather than untidy: two messages under one AES-GCM key and one nonce. The
    IV comparison is what makes that a failing test rather than a code comment.
    """
    with make_client(service, signing_key_pem) as client:
        client.push_backup(EXTERNAL_ID, PLAINTEXT, name="medlemsregister.sql.gz")

    registered = next(call for call in service.calls if call.step == FOUR_CALLS[1]).json()
    dek = crypto.unwrap_dek(base64.b64decode(registered["wrappedDekB64"]), tenant_key)
    name_blob = base64.b64decode(registered["nameCipherB64"])

    assert crypto.decrypt(name_blob, dek) == b"medlemsregister.sql.gz"
    assert decode_header(name_blob) != decode_header(service.uploaded)


def test_no_name_is_sent_when_none_is_given(service, signing_key_pem):
    with make_client(service, signing_key_pem) as client:
        client.push_backup(EXTERNAL_ID, PLAINTEXT)

    registered = next(call for call in service.calls if call.step == FOUR_CALLS[1]).json()
    assert "nameCipherB64" not in registered


# -------------------------------------------------------------- what refusals mean


def test_409_on_registering_is_retryable_and_says_why(service, signing_key_pem):
    service.fail_at = FOUR_CALLS[1]
    service.failure = (409, DETAIL_409)

    with (
        make_client(service, signing_key_pem) as client,
        pytest.raises(VaultNotInitialized) as raised,
    ):
        client.push_backup(EXTERNAL_ID, PLAINTEXT)

    error = raised.value
    assert error.retryable is True
    assert error.status == 409
    assert error.code == "tenant_not_initialized"
    assert "step 2 of 4" in str(error)
    # The sentence an operator reads instead of going to look for a fault.
    assert "Nobody has started this vault yet" in str(error)


def test_409_on_the_public_key_is_the_same_answer(service, signing_key_pem):
    """Both of the first two calls answer it, and both mean "not yet"."""
    service.fail_at = FOUR_CALLS[0]
    service.failure = (409, b'{"code":"tenant_not_initialized"}')

    with (
        make_client(service, signing_key_pem) as client,
        pytest.raises(VaultNotInitialized) as raised,
    ):
        client.push_backup(EXTERNAL_ID, PLAINTEXT)

    assert raised.value.retryable is True
    assert "step 1 of 4" in str(raised.value)


@pytest.mark.parametrize(
    ("status", "body", "code"),
    [
        (413, b'{"code":"too_large","detail":"exceeds the cap"}', "too_large"),
        (400, b'{"code":"checksum_mismatch"}', "checksum_mismatch"),
        (404, b'{"code":"tenant_not_found"}', "tenant_not_found"),
        (422, b'{"code":"invalid_request"}', "invalid_request"),
        # A 409 that is *not* retryable, next to two that are. Sending the same
        # request again cannot change the answer: the key is already bound to a
        # different one.
        (409, b'{"code":"idempotency_key_reused"}', "idempotency_key_reused"),
    ],
)
def test_other_refusals_are_not_retryable(service, signing_key_pem, status, body, code):
    """The other side of the 409: everything else needs a person.

    A client that reported every 4xx as retryable would pass the 409 test above
    and turn a permanent misconfiguration into a schedule that retries forever.
    """
    service.fail_at = FOUR_CALLS[1]
    service.failure = (status, body)

    with make_client(service, signing_key_pem) as client, pytest.raises(ApiError) as raised:
        client.push_backup(EXTERNAL_ID, PLAINTEXT)

    assert raised.value.retryable is False
    assert raised.value.code == code
    assert not isinstance(raised.value, VaultNotInitialized)


def test_a_spent_quota_is_retryable_but_is_not_an_unstarted_vault(service, signing_key_pem):
    service.fail_at = FOUR_CALLS[1]
    service.failure = (429, b'{"code":"quota_exceeded","detail":"storage limit"}')

    with (
        make_client(service, signing_key_pem) as client,
        pytest.raises(QuotaExceeded) as raised,
    ):
        client.push_backup(EXTERNAL_ID, PLAINTEXT)

    assert raised.value.retryable is True
    assert not isinstance(raised.value, VaultNotInitialized)


def test_a_first_attempt_still_running_is_retryable(service, signing_key_pem):
    """The 409 that means "not yet", as against the 409 that means "not ever".

    A request that timed out on the wire and is retried inside the window is
    exactly what the `Idempotency-Key` is sent for, and the honest answer while
    the first attempt is still working is to come back in a moment. Reporting
    it as fatal would abandon a backup that is at that moment succeeding.
    """
    service.fail_at = FOUR_CALLS[1]
    service.failure = (
        409,
        b'{"code":"idempotency_in_progress","detail":"still running"}',
    )

    with (
        make_client(service, signing_key_pem) as client,
        pytest.raises(RequestInFlight) as raised,
    ):
        client.push_backup(EXTERNAL_ID, PLAINTEXT)

    assert raised.value.retryable is True
    assert raised.value.code == "idempotency_in_progress"
    assert not isinstance(raised.value, VaultNotInitialized)


def test_a_vault_that_filled_up_mid_push_is_retryable(service, signing_key_pem):
    """The 409 that arrives after the bytes were sent.

    Distinct from `quota_exceeded`, which refuses before an upload URL exists.
    This one means another push finished in between; the server discarded what
    this one uploaded and touched nothing already stored. The next run is
    expected to succeed, so it is retryable -- but the whole push repeats,
    because the blob is gone.
    """
    service.fail_at = FOUR_CALLS[3]
    service.failure = (
        409,
        b'{"code":"storage_full","detail":"storing this backup would leave 120 bytes"}',
    )

    with (
        make_client(service, signing_key_pem) as client,
        pytest.raises(StorageFull) as raised,
    ):
        client.push_backup(EXTERNAL_ID, PLAINTEXT)

    assert raised.value.retryable is True
    assert raised.value.code == "storage_full"
    assert not isinstance(raised.value, QuotaExceeded)


def test_an_authorizer_denial_becomes_an_auth_error(service, signing_key_pem):
    """API Gateway writes its own body, with no Datavalv code in it.

    The client must still say something useful. A parser that required `code`
    would raise a KeyError here — inside the error path, where it is hardest to
    read.
    """
    service.fail_at = FOUR_CALLS[0]
    service.failure = (403, b'{"message":"Forbidden"}')

    with make_client(service, signing_key_pem) as client, pytest.raises(AuthError) as raised:
        client.push_backup(EXTERNAL_ID, PLAINTEXT)

    error = raised.value
    assert error.code is None
    assert error.status == 403
    assert error.retryable is False
    assert "Forbidden" in str(error)
    assert "/applications" in str(error)


def test_an_upload_refusal_names_storage_and_the_step(service, signing_key_pem):
    service.fail_at = "PUT upload"
    service.failure = (403, b"<Error><Code>AccessDenied</Code></Error>")

    with make_client(service, signing_key_pem) as client, pytest.raises(UploadError) as raised:
        client.push_backup(EXTERNAL_ID, PLAINTEXT)

    message = str(raised.value)
    assert "step 3 of 4" in message
    assert "AccessDenied" in message
    assert "expired upload link" in message


def test_a_network_failure_is_retryable_and_names_the_step(signing_key_pem):
    def refuse(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("nodename nor servname provided", request=request)

    client = DatavalvClient(
        API_BASE, CLIENT_ID, KEY_ID, signing_key_pem, transport=httpx.MockTransport(refuse)
    )
    with client, pytest.raises(NetworkError) as raised:
        client.push_backup(EXTERNAL_ID, PLAINTEXT)

    assert raised.value.retryable is True
    assert "step 1 of 4" in str(raised.value)


# ------------------------------------------------------------------- vaults


def test_create_vault_sends_only_what_it_was_given(service, signing_key_pem):
    """Unset fields are omitted, not nulled.

    `CreateTenantRequest` forbids unknown fields and defaults the rest;
    `"locale": null` fails validation rather than meaning "use the default", so
    a client that sent every field always would 422 on the commonest call.
    """
    with make_client(service, signing_key_pem) as client:
        vault = client.create_vault(EXTERNAL_ID, "anna@example.se")

    assert vault.tenant_id == "t-1"
    assert vault.status == "provisioned"
    body = service.calls[0].json()
    assert body == {"externalId": EXTERNAL_ID, "ownerEmail": "anna@example.se"}


def test_create_vault_passes_the_optional_fields_through(service, signing_key_pem):
    with make_client(service, signing_key_pem) as client:
        client.create_vault(
            EXTERNAL_ID, "anna@example.se", name="Kund 4711", locale="en", retention_count=7
        )

    assert service.calls[0].json() == {
        "externalId": EXTERNAL_ID,
        "ownerEmail": "anna@example.se",
        "name": "Kund 4711",
        "locale": "en",
        "retentionCount": 7,
    }


def test_set_retention_patches_the_vault(service, signing_key_pem):
    """The one source-app route neither client wrapped.

    Retention is settable at creation and changeable for the life of the
    vault, and until this the second half meant composing and signing the call
    by hand -- which is the part of this protocol a client exists to do for
    you.
    """
    with make_client(service, signing_key_pem) as client:
        client.set_retention(EXTERNAL_ID, 12)

    call = service.calls[0]
    assert call.method == "PATCH"
    assert call.url.path == f"/v1/tenants/{EXTERNAL_ID}"
    assert call.json() == {"retentionCount": 12}


@pytest.mark.parametrize("count", [0, -1, 366, 1.5])
def test_set_retention_refuses_a_count_the_api_would_refuse(service, signing_key_pem, count):
    """Checked here rather than left to the 422.

    The server's range is 1-365, and a client that sends 0 spends a signed
    call and a round trip to be told what it could have known. `1.5` is in
    here because a float that happens to be whole would be sent as `1.5` and
    read as invalid_request, which is a confusing way to learn you did
    arithmetic.
    """
    with make_client(service, signing_key_pem) as client, pytest.raises(ConfigurationError):
        client.set_retention(EXTERNAL_ID, count)

    assert service.calls == []


def test_delete_vault_sends_the_confirmation_the_api_asks_for(service, signing_key_pem):
    """The most destructive route in the API, and the only one with a guard.

    `DeleteTenantRequest.confirm` must repeat the identifier in the path, or
    the service answers `confirmation_mismatch`. The client sends it rather
    than the caller composing the body, but it does not *invent* it -- see the
    test below.
    """
    with make_client(service, signing_key_pem) as client:
        deleted = client.delete_vault(EXTERNAL_ID, confirm=EXTERNAL_ID)

    assert deleted.tenant_id == "t-1"
    assert deleted.status == "deleted"
    call = service.calls[0]
    assert call.method == "DELETE"
    assert call.url.path == f"/v1/tenants/{EXTERNAL_ID}"
    assert call.json() == {"confirm": EXTERNAL_ID}


def test_delete_vault_will_not_confirm_on_the_callers_behalf(service, signing_key_pem):
    """`confirm` is keyword-only and has no default, and a mismatch never goes out.

    A client that defaulted it to `external_id` would be a client that defeats
    the guard for everybody: the API asks for the identifier twice precisely so
    that one wrong variable cannot delete a customer's backups, and deriving
    the second from the first is the one implementation that cannot fail.
    """
    with (
        make_client(service, signing_key_pem) as client,
        pytest.raises(ConfigurationError, match="confirm"),
    ):
        client.delete_vault(EXTERNAL_ID, confirm="kund-4712")

    assert service.calls == []


def test_list_backups_returns_the_summaries(service, signing_key_pem):
    with make_client(service, signing_key_pem) as client:
        assert client.list_backups(EXTERNAL_ID) == []


# ----------------------------------------------------------------- the rest


def test_an_idempotency_key_is_sent_when_asked_for(service, signing_key_pem):
    with make_client(service, signing_key_pem) as client:
        client.push_backup(EXTERNAL_ID, PLAINTEXT, idempotency_key="nightly-2026-09-17")

    registered = next(call for call in service.calls if call.step == FOUR_CALLS[1])
    assert registered.headers["Idempotency-Key"] == "nightly-2026-09-17"


def test_no_idempotency_header_when_none_was_asked_for(service, signing_key_pem):
    """A missing header is not an error at the API, and must stay missing here.

    Sending a constant would be worse than sending none: two nights under one
    key means the second night replays the first night's response.
    """
    with make_client(service, signing_key_pem) as client:
        client.push_backup(EXTERNAL_ID, PLAINTEXT)

    registered = next(call for call in service.calls if call.step == FOUR_CALLS[1])
    assert "Idempotency-Key" not in registered.headers


@pytest.mark.parametrize("given", [API_BASE, API_BASE + "/", API_BASE + "/v1"])
def test_the_api_base_is_accepted_with_or_without_the_v1(service, signing_key_pem, given):
    """Both spellings are in this project's own runbooks and samples."""
    with DatavalvClient(
        given, CLIENT_ID, KEY_ID, signing_key_pem, transport=httpx.MockTransport(service)
    ) as client:
        client.tenant_public_key(EXTERNAL_ID)

    assert service.calls[0].url.path == f"/v1/tenants/{EXTERNAL_ID}/public-key"


def test_push_accepts_an_open_binary_file(service, signing_key_pem):
    with make_client(service, signing_key_pem) as client:
        pushed = client.push_backup(EXTERNAL_ID, io.BytesIO(PLAINTEXT))

    assert pushed.size == len(service.uploaded)


def test_push_refuses_a_file_opened_in_text_mode(service, signing_key_pem, tmp_path):
    path = tmp_path / "dump.sql"
    path.write_text("select 1;\n")

    with (
        make_client(service, signing_key_pem) as client,
        open(path) as handle,
        pytest.raises(TypeError, match="binary mode"),
    ):
        client.push_backup(EXTERNAL_ID, handle)


def test_a_private_key_path_is_refused_rather_than_read(service):
    """`DATAVALV_PRIVATE_KEY` is a path; this argument is the key.

    Accepting both would make the two interchangeable, which is how a key ends
    up in an environment variable — and in `ps`, and in the shell history.
    """
    with pytest.raises(ConfigurationError, match="looks like a filename"):
        DatavalvClient(API_BASE, CLIENT_ID, KEY_ID, "/etc/datavalv/signing.pem")


def test_missing_settings_are_refused_before_any_request(service):
    for kwargs in (
        {"api_base": "", "client_id": CLIENT_ID, "key_id": KEY_ID},
        {"api_base": API_BASE, "client_id": "", "key_id": KEY_ID},
        {"api_base": API_BASE, "client_id": CLIENT_ID, "key_id": ""},
    ):
        with pytest.raises(ConfigurationError):
            DatavalvClient(kwargs["api_base"], kwargs["client_id"], kwargs["key_id"], "x")

    assert service.calls == []


def test_an_over_long_label_fails_before_the_file_is_encrypted(service, signing_key_pem):
    with (
        make_client(service, signing_key_pem) as client,
        pytest.raises(ValueError, match="caps it at 200"),
    ):
        client.push_backup(EXTERNAL_ID, PLAINTEXT, label="x" * 201)

    assert service.calls == []


# ----------------------------------------------- key material never leaves


def test_a_private_key_in_a_field_is_refused_before_anything_is_sent(service, signing_key_pem):
    """The one mistake this library exists to make impossible, made by hand.

    Nothing here asks for a private key: the signing key is read from a file
    and used to sign, and every field a caller fills in is a name, a label or
    a digest. So a private key in one of them is a paste that went into the
    wrong argument -- and the only useful moment to notice is before the
    request, because afterwards the key has been in somebody else's logs
    whatever they do with it next.
    """
    client = make_client(service, signing_key_pem)
    leaked = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----"

    with pytest.raises(ConfigurationError) as refused:
        client.create_vault(EXTERNAL_ID, "anna@example.se", name=leaked)

    assert "private key" in str(refused.value).lower()
    assert list(service.calls) == [], "the request was sent anyway"


def test_the_refusal_reads_every_spelling_of_a_key_file(service, signing_key_pem):
    """The same shapes `applications.ts` refuses in the browser: any PEM
    label, any case, and PuTTY's own format, which has no BEGIN line."""
    client = make_client(service, signing_key_pem)
    spellings = [
        "-----BEGIN OPENSSH PRIVATE KEY-----\nb3Blbn\n-----END OPENSSH PRIVATE KEY-----",
        "-----begin ec private key-----\nMHcCAQ\n-----end ec private key-----",
        "PuTTY-User-Key-File-3: ssh-rsa\nPrivate-Lines: 14\nAAAA",
    ]

    for spelling in spellings:
        with pytest.raises(ConfigurationError):
            client.create_vault(EXTERNAL_ID, "anna@example.se", name=spelling)

    assert service.calls == []


def test_a_label_that_merely_says_private_key_is_sent(service, signing_key_pem):
    """A guard that refused the words would refuse "nightly private key
    backup", which is a label somebody will legitimately write."""
    client = make_client(service, signing_key_pem)

    client.create_vault(EXTERNAL_ID, "anna@example.se", name="private key backups")

    assert [call.step for call in service.calls] == ["POST /v1/tenants"]


def test_a_push_asked_to_keep_says_so_to_the_service(service, signing_key_pem):
    """Retention never removes a kept copy; the service is the one to be told."""
    client = make_client(service, signing_key_pem)

    pushed = client.push_backup(EXTERNAL_ID, PLAINTEXT, keep=True)

    declared = [c for c in service.calls if c.step == f"POST /v1/tenants/{EXTERNAL_ID}/backups"]
    assert declared[0].json()["keep"] is True
    assert pushed.kept is True


def test_an_ordinary_push_sends_no_keep_at_all(service, signing_key_pem):
    """Absent rather than `false`, so the body an ordinary push sends is the one
    it always sent."""
    client = make_client(service, signing_key_pem)

    pushed = client.push_backup(EXTERNAL_ID, PLAINTEXT)

    declared = [c for c in service.calls if c.step == f"POST /v1/tenants/{EXTERNAL_ID}/backups"]
    assert "keep" not in declared[0].json()
    assert pushed.kept is False
