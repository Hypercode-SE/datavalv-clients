"""A fake Datavalv, close enough to the real one to catch the real mistakes.

`httpx.MockTransport` answers at the transport layer, so the client under test
builds and sends genuine requests — headers, bodies and all — and nothing here
is a stand-in for the code being tested.

The fake mirrors four rules from `api/src/datavalv_api/`, and each is here
because a client can get it wrong in a way a lazier double would not notice:

* every Datavalv call needs a bearer token, and the token is **verified** —
  signature, `aud`, `iss`, the five required claims, and the 300-second cap on
  `exp - iat` that `authorizer.verify` applies to the issued lifetime;
* a `jti` is accepted **once**, which is what makes a hoisted `Authorization`
  header fail here exactly as it would against the deployed authorizer;
* the presigned `PUT` goes to storage, which knows nothing of Datavalv tokens
  and refuses a request that carries a second set of credentials; and
* that `PUT` must carry `x-amz-checksum-sha256`, because `objects.presigned_put`
  signs `ChecksumSHA256` into the URL and S3 rejects a request that omits a
  signed header.
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass, field

import httpx
import jwt
import pytest

from datavalv_client import crypto

CLIENT_ID = "9fd31abd-e7ac-4d06-97c9-f9125f829bc4"
KEY_ID = "3783178c-9fe3-4a1c-aba5-6a4ee9478a5c"
TENANT_KEY_ID = "0f1c0a2b-8d5e-4a77-9c31-2b6d4e8f10aa"
EXTERNAL_ID = "kund-4711"
BACKUP_ID = "bk_01J8Z6QK9T"
UPLOAD_URL = "https://datavalv-staging.s3.eu-north-1.amazonaws.com/tenants/t1/bk.dvlv?sig=x"
API_BASE = "https://api-staging.datavalv.se"

#: The authorizer's own cap on `exp - iat`, restated so the test asserts
#: against the rule rather than against this client's choice of lifetime.
MAX_ISSUED_LIFETIME = 300


@dataclass
class Call:
    """One request the client made."""

    method: str
    url: httpx.URL
    headers: httpx.Headers
    content: bytes

    @property
    def path(self) -> str:
        return self.url.path

    @property
    def step(self) -> str:
        """A short name for the protocol step, for order assertions.

        The upload is told apart by its path rather than its host: everything
        Datavalv answers is under `/v1/`, and the presigned URL is a bucket key.
        """
        if not self.url.path.startswith("/v1/"):
            return "PUT upload"
        return f"{self.method} {self.url.path}"

    def json(self) -> dict:
        return json.loads(self.content)

    @property
    def token(self) -> str | None:
        header = self.headers.get("authorization")
        if not header:
            return None
        assert header.startswith("Bearer "), header
        return header[len("Bearer ") :]


@pytest.fixture(autouse=True)
def _pins_live_in_a_temporary_directory(tmp_path, monkeypatch):
    """The default pin file is in the user's home directory, SSH-style. No test
    may read or write the real one: a suite that pinned a fixture key there
    would make the developer's next real push refuse."""
    monkeypatch.setenv("DATAVALV_KNOWN_VAULTS", str(tmp_path / "known_vaults.json"))


@pytest.fixture(scope="session")
def signing_key():
    """The source application's key. RSA-3072, as `datavalv keygen` makes."""
    return crypto.generate_keypair()


@pytest.fixture(scope="session")
def tenant_key():
    """The vault's key. In production this is made in a member's browser."""
    return crypto.generate_keypair()


@pytest.fixture(scope="session")
def signing_key_pem(signing_key) -> str:
    return crypto.private_key_to_pem(signing_key)


@pytest.fixture(scope="session")
def tenant_public_pem(tenant_key) -> str:
    return crypto.public_key_to_pem(tenant_key.public_key())


@dataclass
class FakeDatavalv:
    """A transport handler standing in for the API and for S3.

    `fail_at` names a step by its `Call.step` spelling; the first request
    matching it is answered with `failure` instead of the happy path. That is
    how the ordering tests break one link and check that nothing after it ran.
    """

    signing_public_pem: str
    tenant_public_pem: str
    fail_at: str | None = None
    failure: tuple[int, bytes] = (500, b'{"code":"internal_error"}')
    calls: list[Call] = field(default_factory=list)
    seen_jtis: set[str] = field(default_factory=set)
    uploaded: bytes | None = None

    # -- the authorizer, in miniature -------------------------------------

    def _verify(self, call: Call) -> httpx.Response | None:
        token = call.token
        if token is None:
            # What API Gateway answers when there is no Authorization header at
            # all. The body is its own, not Datavalv's error shape.
            return httpx.Response(401, json={"message": "Unauthorized"})

        header = jwt.get_unverified_header(token)
        if header.get("kid") != KEY_ID:
            return httpx.Response(403, json={"message": "Forbidden"})

        try:
            claims = jwt.decode(
                token,
                self.signing_public_pem,
                algorithms=["RS256", "ES256"],
                audience="datavalv",
                issuer=CLIENT_ID,
                options={"require": ["exp", "iat", "iss", "aud", "jti"]},
            )
        except jwt.PyJWTError:
            return httpx.Response(403, json={"message": "Forbidden"})

        if int(claims["exp"]) - int(claims["iat"]) > MAX_ISSUED_LIFETIME:
            return httpx.Response(403, json={"message": "Forbidden"})

        jti = str(claims["jti"])
        if jti in self.seen_jtis:
            # The single-use rule. `store.record_jti` raises `TokenReplayed`,
            # the authorizer denies, and `enable_simple_responses` turns the
            # denial into a 403.
            return httpx.Response(403, json={"message": "Forbidden"})
        self.seen_jtis.add(jti)
        return None

    # -- routing -----------------------------------------------------------

    def __call__(self, request: httpx.Request) -> httpx.Response:
        call = Call(
            method=request.method,
            url=request.url,
            headers=request.headers,
            content=request.content,
        )
        self.calls.append(call)

        if call.step == self.fail_at:
            status, body = self.failure
            return httpx.Response(status, content=body)

        if call.step == "PUT upload":
            return self._upload(call)

        denial = self._verify(call)
        if denial is not None:
            return denial
        return self._route(call)

    def _upload(self, call: Call) -> httpx.Response:
        if call.headers.get("authorization"):
            # S3 refuses a presigned request that also carries an
            # Authorization header: two sets of credentials on one request.
            return httpx.Response(
                400,
                content=b"<Error><Code>InvalidArgument</Code><Message>Only one auth "
                b"mechanism allowed</Message></Error>",
            )
        checksum = call.headers.get("x-amz-checksum-sha256")
        if not checksum:
            # The URL signs ChecksumSHA256, so the header is required rather
            # than merely accepted.
            return httpx.Response(
                403,
                content=b"<Error><Code>SignatureDoesNotMatch</Code></Error>",
            )
        if base64.b64decode(checksum) != hashlib.sha256(call.content).digest():
            return httpx.Response(400, content=b"<Error><Code>BadDigest</Code></Error>")
        self.uploaded = call.content
        return httpx.Response(200, headers={"x-amz-checksum-sha256": checksum})

    def _route(self, call: Call) -> httpx.Response:
        path, method = call.url.path, call.method

        if method == "GET" and path == f"/v1/tenants/{EXTERNAL_ID}/public-key":
            return httpx.Response(
                200,
                json={
                    "tenantId": "t-1",
                    "keyId": TENANT_KEY_ID,
                    "publicKeyPem": self.tenant_public_pem,
                },
            )
        if method == "POST" and path == f"/v1/tenants/{EXTERNAL_ID}/backups":
            return httpx.Response(
                201,
                json={"backupId": BACKUP_ID, "uploadUrl": UPLOAD_URL, "expiresIn": 900},
            )
        if method == "POST" and path == f"/v1/backups/{BACKUP_ID}/complete":
            return httpx.Response(200, json={"status": "available", "pruned": 0})
        if method == "POST" and path == "/v1/tenants":
            return httpx.Response(201, json={"tenantId": "t-1", "status": "provisioned"})
        if method == "PATCH" and path == f"/v1/tenants/{EXTERNAL_ID}":
            return httpx.Response(200, json={"status": "ok"})
        if method == "DELETE" and path == f"/v1/tenants/{EXTERNAL_ID}":
            return httpx.Response(200, json={"tenantId": "t-1", "status": "deleted"})
        if method == "GET" and path == f"/v1/tenants/{EXTERNAL_ID}/backups":
            return httpx.Response(200, json={"backups": []})

        return httpx.Response(404, json={"code": "not_found", "detail": path})


@pytest.fixture
def service(signing_key, tenant_public_pem) -> FakeDatavalv:
    return FakeDatavalv(
        signing_public_pem=crypto.public_key_to_pem(signing_key.public_key()),
        tenant_public_pem=tenant_public_pem,
    )
