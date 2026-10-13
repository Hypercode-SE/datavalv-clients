"""The HTTP layer: four calls, in one order, with one token each.

`api/src/datavalv_api/` is the authority for all of it, and the two public pages
that describe it — `/connect-system` step 08 and `/developers` — were verified
against that source. This module is the same protocol as code.

One backup costs four calls:

1. ``GET  /v1/tenants/{externalId}/public-key`` → ``keyId``, ``publicKeyPem``
2. ``POST /v1/tenants/{externalId}/backups`` → ``backupId``, ``uploadUrl``
3. ``PUT  {uploadUrl}`` — the ciphertext, with ``x-amz-checksum-sha256``
4. ``POST /v1/backups/{backupId}/complete``

Four details are load-bearing and none of them is visible from the call list:

* **The key from step 1 is not taken on the service's word.** The service is
  the one party this design does not trust with plaintext, and it is the party
  that names the key every backup is encrypted to. `push_backup` remembers the
  fingerprint of the first key it is given for a vault and refuses a different
  one before encrypting anything. See `pins.py`.

* **A token is spent on arrival.** `authorizer.verify` records every `jti` and
  the authorizer's result is cached for zero seconds, so each of the three
  Datavalv calls mints its own. See `tokens.py`.
* **The digest is of the ciphertext**, never the plaintext, and it travels
  twice in two spellings: hex in the JSON body, base64 of the same bytes in the
  S3 header. `_push` computes it once and encodes it twice, which is the only
  arrangement in which the two cannot disagree.
* **The `PUT` carries no `Authorization`.** The URL is presigned; an
  `Authorization` header alongside it is a second set of credentials on one
  request, and S3 refuses that. It is also the one call that does not go to
  Datavalv at all.

A backup exists for the service only after step 4. Three of four leaves a
`pending` row and an object that no reader will ever be offered — which is why
`push_backup` is one method rather than four, and why a failure anywhere in it
raises rather than returning something partial.
"""

from __future__ import annotations

import base64
import hashlib
import json as json_module
import re
from dataclasses import dataclass, replace
from typing import IO, Any, Self

import httpx
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

from . import crypto, tokens
from .errors import (
    STEP_COMPLETE,
    STEP_CREATE_VAULT,
    STEP_DELETE_VAULT,
    STEP_PUBLIC_KEY,
    STEP_REGISTER,
    STEP_SET_RETENTION,
    STEP_UPLOAD,
    ConfigurationError,
    NetworkError,
    UploadError,
    VaultKeyChanged,
    from_response,
)
from .format import decode_header
from .pins import FilePins, KeyPins

#: Generous on write, bounded on connect.
#:
#: The upload is the one call whose body can be gigabytes, and a write timeout
#: sized for a JSON request would kill a large backup part-way — leaving
#: exactly the three-of-four state step 4 exists to prevent. Connect stays
#: short: a name that does not resolve should fail now, not in ten seconds.
DEFAULT_TIMEOUT = httpx.Timeout(connect=10.0, read=60.0, write=900.0, pool=10.0)

#: The `label` cap from `models.CreateBackupRequest`, checked here so that a
#: too-long note fails before the file has been encrypted and uploaded rather
#: than as a `422` on step 2.
MAX_LABEL_LENGTH = 200

#: The `nameCipherB64` cap from `models.NameCipherB64`, in base64 characters.
#: 512 of them hold 347 bytes of UTF-8 filename once the 37 bytes of format
#: overhead are paid, comfortably above any filename a source server can have
#: opened — so this is a guard against a caller passing something that is not a
#: filename, not a limit a real push meets.
MAX_NAME_CIPHER_B64 = 512


@dataclass(frozen=True)
class PushedBackup:
    """What a completed push produced.

    `sha256` is the ciphertext's digest, hex — the same value the service
    stored and the same one it verified against S3 before marking the backup
    available.
    """

    backup_id: str
    size: int
    sha256: str
    key_id: str
    pruned: int
    #: The fingerprint of the key this copy was encrypted to --
    #: `crypto.public_key_fingerprint`, the string the vault's owner is shown
    #: under their backups.
    key_fingerprint: str = ""
    #: Whether this push was the first time this machine saw that key. The one
    #: moment the fingerprint is worth reading out to somebody: compared once
    #: with the owner's, the pin is the vault's key and not merely the first
    #: key this machine was told about.
    key_first_seen: bool = False
    #: Whether this copy was pushed with `keep`: retention never removes it,
    #: and only a vault member can delete it or hand it back to retention.
    kept: bool = False


@dataclass(frozen=True)
class CreatedVault:
    tenant_id: str
    status: str


@dataclass(frozen=True)
class DeletedVault:
    tenant_id: str
    status: str


def _load_private_key(
    private_key: str | bytes | RSAPrivateKey | EllipticCurvePrivateKey,
) -> RSAPrivateKey | EllipticCurvePrivateKey:
    """A signing key from PEM text, or a key object straight through.

    **A path is refused, loudly.** `DATAVALV_PRIVATE_KEY` names a file for a
    reason — a private key in an environment variable is in `ps`, in the shell
    history that set it and in every crash dump of the process — and a caller
    who passes the path here has made the near-miss of that mistake. Reading
    the file for them would be convenient and would make the two spellings
    interchangeable, which is how the variable ends up holding the key.
    """
    if isinstance(private_key, (RSAPrivateKey, EllipticCurvePrivateKey)):
        return private_key
    if isinstance(private_key, (str, bytes)):
        text = private_key.decode() if isinstance(private_key, bytes) else private_key
        if "-----BEGIN" not in text:
            raise ConfigurationError(
                "private_key must be PEM text or a loaded key object; this looks "
                "like a filename. Read the file and pass its contents — and keep "
                "the key itself out of environment variables."
            )
        try:
            return crypto.load_private_key_pem(text)
        except Exception as exc:
            raise ConfigurationError(f"private_key is not a usable PEM key: {exc}") from exc
    raise ConfigurationError(
        f"private_key must be PEM text or a key object, not {type(private_key).__name__}"
    )


#: The shapes a private key really arrives in, matched against every JSON
#: body before it is sent.
#:
#: **Nothing this library sends has a field for a key.** The signing key is
#: read from a file and used to sign; every value a caller fills in is a name,
#: a label, a digest or a wrapped DEK. So a private key in one of them is a
#: paste that went into the wrong argument, and the only useful moment to
#: notice is before the request: afterwards it has been in somebody else's
#: logs whatever they do about it next.
#:
#: A *block*, not the words -- "nightly private key backup" is a label
#: somebody will legitimately write. `[^-]*` between BEGIN and PRIVATE KEY is
#: what carries the labels: plain, RSA, EC, ENCRYPTED, OPENSSH, PGP. PuTTY's
#: own format has no BEGIN line at all and is matched by its header.
#:
#: The same shapes `web/src/app/pages/applications/applications.ts` refuses in
#: the browser, for the same reason.
_PRIVATE_KEY_SHAPES = (
    re.compile(r"-{3,}\s*BEGIN[^-]*PRIVATE KEY\s*-{3,}", re.IGNORECASE),
    re.compile(r"PuTTY-User-Key-File", re.IGNORECASE),
    re.compile(r"^Private-Lines:", re.IGNORECASE | re.MULTILINE),
)


def _refuse_key_material(body: dict[str, Any] | None) -> None:
    """Raise before a request carrying a private key can be made."""
    if body is None:
        return
    text = json_module.dumps(body)
    if any(shape.search(text) for shape in _PRIVATE_KEY_SHAPES):
        raise ConfigurationError(
            "this request carries what looks like a private key, so nothing was "
            "sent. Datavalv never needs one: the signing key stays on your "
            "server and is used to sign, and no field here is for key material."
        )


class DatavalvClient:
    """A source application's connection to Datavalv.

    `api_base` may be given with or without the ``/v1`` suffix; both spellings
    are in this project's own runbooks, so both are accepted and normalised
    here rather than producing a `404` whose cause is a doubled path segment.

    `private_key` is PEM text or an already-loaded key object. Never a path —
    see `_load_private_key`.

    `pins` is where each vault's key fingerprint is remembered so that a changed
    key is refused (`pins.py`). Left out, it is `FilePins.default()` -- a file
    in the user's state directory, or wherever `DATAVALV_KNOWN_VAULTS` points --
    because the protection has to hold across processes to mean anything for a
    scheduled job, and a default that remembered nothing would be a default
    that protected nothing. Pass `MemoryPins({...})` with fingerprints from
    configuration on a machine that has no disk to remember on.
    """

    def __init__(
        self,
        api_base: str,
        client_id: str,
        key_id: str,
        private_key: str | bytes | RSAPrivateKey | EllipticCurvePrivateKey,
        *,
        timeout: httpx.Timeout | float = DEFAULT_TIMEOUT,
        transport: httpx.BaseTransport | None = None,
        pins: KeyPins | None = None,
    ) -> None:
        if not api_base:
            raise ConfigurationError("api_base is required, e.g. https://api.datavalv.se")
        if not client_id:
            raise ConfigurationError("client_id is required; it is what /applications issued")
        if not key_id:
            raise ConfigurationError("key_id is required; it is the kid of the registered key")

        self.api_base = api_base.rstrip("/").removesuffix("/v1")
        self.client_id = client_id
        self.key_id = key_id
        self._private_key = _load_private_key(private_key)
        self.pins: KeyPins = pins if pins is not None else FilePins.default()
        self._http = httpx.Client(timeout=timeout, transport=transport, follow_redirects=False)

    # -- lifecycle ---------------------------------------------------------

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- the calls ---------------------------------------------------------

    def _auth(self) -> dict[str, str]:
        """One header, one request. Never hoisted — see `tokens`."""
        return tokens.authorization_header(
            client_id=self.client_id,
            key_id=self.key_id,
            private_key=self._private_key,
        )

    def _call(
        self,
        method: str,
        path: str,
        *,
        step: str,
        json: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> httpx.Response:
        # Before the token is even spent: a body that carries key material is
        # a mistake to stop, not to report afterwards.
        _refuse_key_material(json)
        request_headers = {**self._auth(), **(headers or {})}
        try:
            response = self._http.request(
                method, f"{self.api_base}{path}", json=json, headers=request_headers
            )
        except httpx.HTTPError as exc:
            raise NetworkError(step=step, cause=exc) from exc

        if response.status_code >= 400:
            raise from_response(step=step, status=response.status_code, body=response.content)
        return response

    def tenant_public_key(self, external_id: str) -> dict[str, str]:
        """Step 1: the vault's public key, and the id of the key it is.

        `409 tenant_not_initialized` here is `VaultNotInitialized`, which
        reports itself retryable: the vault's key is made in the first member's
        browser, so before that first sign-in there is nothing to fetch.
        """
        response = self._call("GET", f"/v1/tenants/{external_id}/public-key", step=STEP_PUBLIC_KEY)
        return response.json()

    def create_backup(
        self,
        external_id: str,
        *,
        size: int,
        sha256_hex: str,
        wrapped_dek_b64: str,
        iv_b64: str,
        key_id: str,
        label: str | None = None,
        name_cipher_b64: str | None = None,
        keep: bool = False,
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        """Step 2: declare the copy and get somewhere to put it.

        `sha256_hex` is the digest of the **ciphertext**. The service signs it
        and `size` into the presigned URL, so a body that disagrees with either
        is refused by S3 itself rather than trusted and stored.

        `idempotency_key` is worth sending from a schedule that retries a run
        that timed out: without it a retry inside the window mints a second
        backup id, consumes quota twice and stores the same night twice.
        """
        body: dict[str, Any] = {
            "size": size,
            "sha256": sha256_hex,
            "wrappedDekB64": wrapped_dek_b64,
            "ivB64": iv_b64,
            "keyId": key_id,
        }
        if label is not None:
            body["label"] = label
        if name_cipher_b64 is not None:
            body["nameCipherB64"] = name_cipher_b64
        # Only when asked for, so an ordinary push sends the body it always did.
        if keep:
            body["keep"] = True

        headers = {"Idempotency-Key": idempotency_key} if idempotency_key else None
        response = self._call(
            "POST",
            f"/v1/tenants/{external_id}/backups",
            step=STEP_REGISTER,
            json=body,
            headers=headers,
        )
        return response.json()

    def upload_ciphertext(self, upload_url: str, blob: bytes, *, sha256_hex: str) -> None:
        """Step 3: the ciphertext, to the presigned URL, with the checksum.

        The header is **required, not optional**: `objects.presigned_put` signs
        `ChecksumSHA256` into the URL, and S3 rejects a request that omits a
        signed header. The value is base64 of the same bytes `sha256_hex`
        spells in hex — which is why this takes the hex and converts, rather
        than taking a second argument that could be a different digest.

        No `Authorization` header: the URL carries its own signature, and a
        second set of credentials on the request is refused.
        """
        checksum_b64 = base64.b64encode(bytes.fromhex(sha256_hex)).decode()
        try:
            response = self._http.put(
                upload_url,
                content=blob,
                headers={"x-amz-checksum-sha256": checksum_b64},
            )
        except httpx.HTTPError as exc:
            raise NetworkError(step=STEP_UPLOAD, cause=exc) from exc

        if response.status_code >= 400:
            raise UploadError(status=response.status_code, body=response.text)

    def complete_backup(self, backup_id: str) -> dict[str, Any]:
        """Step 4: the service checks S3 itself, then the copy counts.

        Until this returns, the backup is `pending`: it is not listed as
        available, and retention has not pruned anything — so the previous good
        copy is still there. That ordering is the product's central promise and
        is `routes_backups.complete_backup`'s doing, not this client's.
        """
        response = self._call("POST", f"/v1/backups/{backup_id}/complete", step=STEP_COMPLETE)
        return response.json()

    # -- vaults ------------------------------------------------------------

    def create_vault(
        self,
        external_id: str,
        owner_email: str,
        *,
        name: str | None = None,
        locale: str | None = None,
        retention_count: int | None = None,
    ) -> CreatedVault:
        """One vault, for one customer whose copies this server will push.

        `owner_email` is the whole of the connection between a vault and the
        person who will own it: there is no invitation link and no code, and the
        vault appears only to a signed-in account whose *confirmed* address is
        identical to this one. A typo here succeeds, mails nobody who will read
        it, and is reported as an error to no one. Read it back to the customer
        before calling.

        `locale` is supplied, never detected — no browser is involved in this
        call, so nothing on the path can observe what the owner reads. Omitted,
        the bootstrap invitation is written in Swedish.

        Fields left `None` are omitted rather than sent as null: the request
        model forbids unknown fields and applies its own defaults, and
        `"locale": null` is a `422` rather than "use the default".
        """
        body: dict[str, Any] = {"externalId": external_id, "ownerEmail": owner_email}
        if name is not None:
            body["name"] = name
        if locale is not None:
            body["locale"] = locale
        if retention_count is not None:
            body["retentionCount"] = retention_count

        response = self._call("POST", "/v1/tenants", step=STEP_CREATE_VAULT, json=body)
        payload = response.json()
        return CreatedVault(tenant_id=payload["tenantId"], status=payload["status"])

    def set_retention(self, external_id: str, retention_count: int) -> None:
        """How many copies this vault keeps, changed for a vault that exists.

        Retention is settable at creation and changeable for the life of the
        vault, and until this method the second half meant composing and
        signing the call by hand -- which is the part of this protocol a
        client exists to do for you.

        **Nothing is deleted when this returns.** Retention runs when the next
        copy is confirmed, so lowering the number takes effect on the next
        push rather than now; a vault that is never pushed to again keeps
        every copy it has. `routes_backups.prune` is where that happens.

        The range is checked here rather than left to the `422`, because a
        signed call and a round trip is a slow way to be told something this
        client already knew. `bool` is refused with everything else that is
        not an `int`: `True` is `1` in Python, and a retention of one is a
        destructive setting to arrive at by accident.
        """
        if isinstance(retention_count, bool) or not isinstance(retention_count, int):
            raise ConfigurationError(
                f"retention_count must be a whole number of copies, not {retention_count!r}"
            )
        if not 1 <= retention_count <= 365:
            raise ConfigurationError(
                f"retention_count must be between 1 and 365, not {retention_count}"
            )

        self._call(
            "PATCH",
            f"/v1/tenants/{external_id}",
            step=STEP_SET_RETENTION,
            json={"retentionCount": retention_count},
        )

    def delete_vault(self, external_id: str, *, confirm: str) -> DeletedVault:
        """End a vault: its rows, its objects, and its identifier.

        The most destructive call this client can make. It drops the member
        rows, the backup rows and the pointer, then the service enqueues a
        purge that deletes the objects from storage. Nothing here is
        recoverable, and the identifier is freed for reuse.

        **`confirm` is keyword-only, has no default, and is checked before
        anything is sent.** The API asks for the identifier twice -- once in
        the path and once in the body -- precisely so that one wrong variable
        cannot end a customer's vault, and a client that defaulted `confirm`
        to `external_id` would be the one implementation of that guard which
        cannot fail. So this asks the caller for it, and refuses a mismatch
        here rather than spending a signed call to be told
        `confirmation_mismatch`.
        """
        if confirm != external_id:
            raise ConfigurationError(
                f"confirm must repeat the vault's identifier: expected "
                f"{external_id!r}, got {confirm!r}"
            )

        response = self._call(
            "DELETE",
            f"/v1/tenants/{external_id}",
            step=STEP_DELETE_VAULT,
            json={"confirm": confirm},
        )
        payload = response.json()
        return DeletedVault(tenant_id=payload["tenantId"], status=payload["status"])

    def list_backups(self, external_id: str) -> list[dict[str, Any]]:
        """What the service holds for this vault.

        No key material comes back on this route — a source application pushes
        copies and is never given the means to read one. That is
        `BackupSummary` versus `MemberBackupSummary` in `models.py`, and it is
        deliberate.
        """
        response = self._call("GET", f"/v1/tenants/{external_id}/backups", step="list the copies")
        return response.json()["backups"]

    # -- the whole sequence ------------------------------------------------

    def push_backup(
        self,
        external_id: str,
        data: bytes | bytearray | memoryview | IO[bytes],
        *,
        name: str | None = None,
        label: str | None = None,
        keep: bool = False,
        idempotency_key: str | None = None,
    ) -> PushedBackup:
        """Encrypt, register, upload and confirm. All four, or an exception.

        `data` is bytes or an open binary file. It is read into memory: the size
        and the digest of the *ciphertext* have to be known before step 2 can be
        called at all, so there is no streaming arrangement that would not
        encrypt twice.

        `name` is the original filename. It is encrypted under the same DEK as
        the payload and sent as `nameCipherB64`, so the member who can open the
        backup can read what it was called and nobody else can — a name like
        `medlemsregister-2026-09-30.sql` states what software a club runs, what
        the data is and when it was taken. Pass the basename; a directory is
        nobody's business either.

        `keep` asks the service to hold this copy outside retention: it takes no
        place in the vault's `retentionCount` and stays until a member deletes
        it or releases it. It still counts towards the storage allowance, so a
        schedule that keeps every night fills the vault.
        """
        plaintext = _as_bytes(data)
        if label is not None and len(label) > MAX_LABEL_LENGTH:
            raise ValueError(
                f"label is {len(label)} characters; the service caps it at {MAX_LABEL_LENGTH}"
            )

        key = self.tenant_public_key(external_id)
        fingerprint, first_seen = self._check_key(external_id, key["publicKeyPem"])
        pushed = self._push(
            external_id,
            plaintext,
            key=key,
            name=name,
            label=label,
            keep=keep,
            idempotency_key=idempotency_key,
        )
        return replace(pushed, key_fingerprint=fingerprint, key_first_seen=first_seen)

    def _check_key(self, external_id: str, public_key_pem: str) -> tuple[str, bool]:
        """The fingerprint of the key just offered, and whether it is new here.

        **Between step 1 and everything else, and nowhere later.** Once a DEK
        has been wrapped to a key, whoever holds that key's private half can
        open the copy; a check after the upload would be a check after the
        fact. So a key that is not the one on record raises here, before a
        byte is encrypted, and the pin is left exactly as it was -- a client
        that re-pinned on a mismatch would refuse once and then comply.

        The first key seen for a vault is recorded and reported as such. That
        is trust on first use, and the caller is told so that a person can turn
        it into more than that by comparing the fingerprint once.
        """
        offered = crypto.public_key_fingerprint(public_key_pem)
        pinned = self.pins.get(self.api_base, self.client_id, external_id)
        if pinned is None:
            self.pins.set(self.api_base, self.client_id, external_id, offered)
            return offered, True
        if pinned != offered:
            raise VaultKeyChanged(
                external_id=external_id,
                pinned=pinned,
                offered=offered,
                where=f"`datavalv vault key --external-id {external_id} --forget`",
            )
        return offered, False

    def _push(
        self,
        external_id: str,
        plaintext: bytes,
        *,
        key: dict[str, str],
        name: str | None,
        label: str | None,
        keep: bool,
        idempotency_key: str | None,
    ) -> PushedBackup:
        dek = crypto.generate_dek()
        blob = crypto.encrypt(plaintext, dek)
        # The IV is read back out of the header rather than generated here and
        # passed in. `crypto.encrypt` draws its own, and a second copy of that
        # value in this module is a second thing that can be wrong about what
        # was actually used to encrypt.
        iv = decode_header(blob)
        wrapped_dek = crypto.wrap_dek(dek, crypto.load_public_key_pem(key["publicKeyPem"]))

        # Computed once. The body carries it as hex and the S3 header as base64
        # of the same bytes; two digests computed separately is the defect that
        # passes an assertion on either one alone.
        digest = hashlib.sha256(blob).digest()
        sha256_hex = digest.hex()

        name_cipher_b64 = None
        if name:
            # No `iv=`: `encrypt` draws a fresh one per call, which is what
            # makes reusing the DEK for this second message safe. Passing the
            # payload's IV here would reuse a nonce under one AES-GCM key,
            # which is catastrophic rather than merely untidy.
            name_cipher_b64 = base64.b64encode(crypto.encrypt(name.encode(), dek)).decode()
            if len(name_cipher_b64) > MAX_NAME_CIPHER_B64:
                raise ValueError(
                    f"the encrypted name is {len(name_cipher_b64)} base64 characters; "
                    f"the service caps nameCipherB64 at {MAX_NAME_CIPHER_B64}. Pass a "
                    "basename rather than a path."
                )

        created = self.create_backup(
            external_id,
            size=len(blob),
            sha256_hex=sha256_hex,
            wrapped_dek_b64=base64.b64encode(wrapped_dek).decode(),
            iv_b64=base64.b64encode(iv).decode(),
            key_id=key["keyId"],
            label=label,
            name_cipher_b64=name_cipher_b64,
            keep=keep,
            idempotency_key=idempotency_key,
        )

        self.upload_ciphertext(created["uploadUrl"], blob, sha256_hex=sha256_hex)
        completed = self.complete_backup(created["backupId"])

        return PushedBackup(
            backup_id=created["backupId"],
            size=len(blob),
            sha256=sha256_hex,
            key_id=key["keyId"],
            pruned=int(completed.get("pruned", 0)),
            kept=keep,
        )


def _as_bytes(data: bytes | bytearray | memoryview | IO[bytes]) -> bytes:
    if isinstance(data, (bytes, bytearray, memoryview)):
        return bytes(data)
    read = getattr(data, "read", None)
    if read is None:
        raise TypeError(
            f"push_backup takes bytes or an open binary file, not {type(data).__name__}"
        )
    chunk = read()
    if isinstance(chunk, str):
        raise TypeError(
            "push_backup needs a file opened in binary mode ('rb'); this one is "
            "in text mode, which would re-encode the bytes it reads"
        )
    return bytes(chunk)


__all__ = ["CreatedVault", "DatavalvClient", "PushedBackup"]
