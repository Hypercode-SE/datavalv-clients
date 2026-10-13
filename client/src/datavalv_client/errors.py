"""What this client raises, and what an operator is told when it does.

Every failure here names the step it happened at and, where the service said
one, the error code from `api/src/datavalv_api/errors.py`. Those codes are API
surface: a source application is meant to branch on them, and `datavalv push`
turns them into exit codes for the same reason.

The distinction the rest of this module exists to draw is **retryable or not**.
A vault whose owner has not signed in yet answers `409 tenant_not_initialized`
to the first two calls, and that is the service working correctly — there is no
key to encrypt against until a member's browser makes one. A schedule that
treats it as a fault sends somebody looking for a broken server on the evening
a customer simply has not logged in yet.
"""

from __future__ import annotations

import json

#: The steps, spelled once. They appear in every error message and in
#: `--verbose` progress, so an operator reading a failure and an operator
#: reading the log are reading the same four names.
#:
#: The numbering is the ordering constraint stated out loud. Three of four
#: leaves a `pending` row and an object nothing will ever mark available, so a
#: message that says which of the four stopped is the difference between
#: knowing that and guessing.
STEP_PUBLIC_KEY = "step 1 of 4, fetch the vault's public key"
STEP_REGISTER = "step 2 of 4, register the copy"
STEP_UPLOAD = "step 3 of 4, upload the encrypted copy"
STEP_COMPLETE = "step 4 of 4, confirm the upload"
STEP_CREATE_VAULT = "create the vault"
STEP_SET_RETENTION = "change how many copies the vault keeps"
STEP_DELETE_VAULT = "delete the vault"


class DatavalvError(Exception):
    """Base for everything this package raises deliberately."""

    #: Whether running the same command again later could succeed with nothing
    #: changed on the source server. False for anything an operator must fix.
    retryable = False


class ConfigurationError(DatavalvError):
    """A missing or unusable setting: no API base, no client id, no key.

    Raised before any request is made, so nothing has happened yet when an
    operator reads it.
    """


class VaultKeyChanged(DatavalvError):
    """The service offered a key for this vault that is not the one on record.

    Raised after step 1 and before anything is encrypted, so nothing has been
    sent. **Not retryable, and never resolved by this client on its own**: a
    vault's key is made once and does not change, so a different one is either
    a vault that was deleted and created again -- a new vault, with a new key
    -- or somebody answering for the service with a key they can open. Only a
    person can tell which, by comparing `offered` with the fingerprint the
    vault's owner sees under their backups.
    """

    def __init__(self, *, external_id: str, pinned: str, offered: str, where: str) -> None:
        self.external_id = external_id
        self.pinned = pinned
        self.offered = offered
        super().__init__(
            f"the key offered for vault {external_id} is not the one this machine has "
            f"seen before. Nothing was encrypted or sent.\n"
            f"  on record: {pinned}\n"
            f"  offered:   {offered}\n"
            "A vault's key never changes. If the vault was deleted and created again, "
            "ask its owner for the fingerprint shown under their backups; if it is the "
            f"offered one, forget the old key ({where}) and push again. If it is not, "
            "do not push, and tell us."
        )


class ApiError(DatavalvError):
    """A refusal from the Datavalv API, with the step it refused.

    `code` is the service's own error code where the body carried one. A denial
    from the authorizer does not: API Gateway answers those itself, with its own
    body, so `code` is then `None` and `status` is the whole of what is known.
    """

    def __init__(
        self,
        *,
        step: str,
        status: int,
        code: str | None = None,
        detail: str | None = None,
    ) -> None:
        self.step = step
        self.status = status
        self.code = code
        self.detail = detail
        super().__init__(self._message())

    #: Appended to the message by subclasses that know what to do about it.
    advice: str | None = None

    def _message(self) -> str:
        named = self.code or f"HTTP {self.status}"
        message = f"{self.step}: {self.status} {named}"
        if self.detail:
            message += f" — {self.detail}"
        if self.advice:
            message += f"\n{self.advice}"
        return message


class AuthError(ApiError):
    """The token was refused: 401 or 403.

    Not retryable, and the distinction matters because the commonest cause is a
    settings mistake rather than a broken key — a `clientId` from one
    registration beside a `kid` from another, or a key retired in
    `/applications` while the server still signs with it.
    """

    advice = (
        "The signing key, the client id or the key id is not what this vault's "
        "registration holds. Check them against /applications, and that the key "
        "there has not been retired."
    )


class VaultNotInitialized(ApiError):
    """`409 tenant_not_initialized`. Expected, and worth waiting out.

    The tenant key is generated in the first member's browser (spec 9.1), so
    between creating a vault and its owner signing in there is genuinely nothing
    to encrypt against. Both `GET .../public-key` and `POST .../backups` answer
    this, and both mean the same thing.
    """

    retryable = True
    advice = (
        "Nobody has started this vault yet: its key is made in the owner's "
        "browser on their first sign-in, and until then there is nothing to "
        "encrypt against. Nothing is broken and nothing on this server needs "
        "changing — let the schedule run again."
    )


class RequestInFlight(ApiError):
    """`409 idempotency_in_progress`. The first attempt is still running.

    Reached by the thing this client sends an `Idempotency-Key` for in the
    first place: a request that timed out on the wire and is being tried again
    while the original is still working. Retryable, and quickly — the answer
    the caller wants is being computed as they read this.

    Treating it as fatal would be worse than having no idempotency key at all:
    it abandons a backup that is at that moment succeeding.
    """

    retryable = True
    advice = (
        "An earlier attempt with this idempotency key has not finished yet. "
        "Wait a few seconds and send the same request again — it will be "
        "answered with the first attempt's result rather than repeating the "
        "work."
    )


class StorageFull(ApiError):
    """`409 storage_full`. The upload completed and was refused for space.

    Distinct from `quota_exceeded`, which refuses before an upload URL is
    issued. This one is only reachable when another push finished in between:
    the bytes were sent, the server declined to store them, and it deleted
    them. Nothing of yours was touched -- the refusal happens before retention
    pruning, so the backups you already had are exactly where they were.

    Retryable, and the whole push must be repeated rather than the upload
    retried: the blob is gone and its upload URL names an object that no longer
    exists.
    """

    retryable = True
    advice = (
        "The vault filled up between declaring this backup and finishing it, "
        "so it was not stored and the uploaded copy was discarded. Nothing "
        "already in the vault was affected. Run the push again; if it keeps "
        "happening, the vault needs a larger allowance."
    )


class QuotaExceeded(ApiError):
    """`429 quota_exceeded`. Retryable in the sense that time may fix it."""

    retryable = True
    advice = "The account's quota is spent. A later run may succeed; see /pricing."


class UploadError(DatavalvError):
    """The `PUT` to storage failed.

    Separate from `ApiError` because the responder is S3, not Datavalv: the
    status codes are S3's, the body is XML, and no Datavalv error code exists
    for any of it. The two causes worth naming are in `advice`.
    """

    def __init__(self, *, status: int, body: str = "", step: str = STEP_UPLOAD) -> None:
        self.status = status
        self.body = body
        self.step = step
        message = f"{step}: storage answered {status}"
        if body:
            message += f" — {body}"
        if status == 403:
            message += (
                "\nA 403 here is usually an expired upload link (they last 15 "
                "minutes) or a body that does not match the size and checksum "
                "signed into it."
            )
        super().__init__(message)


class NetworkError(DatavalvError):
    """The request never got an answer: DNS, TCP, TLS, or a timeout.

    Retryable, and said so rather than left to inference. A nightly push that
    lost its network is not a misconfigured server, and the message carries the
    step so that "it never reached us" and "it reached us and was refused" do
    not look alike in a log.
    """

    retryable = True

    def __init__(self, *, step: str, cause: BaseException) -> None:
        self.step = step
        self.cause = cause
        super().__init__(f"{step}: {type(cause).__name__}: {cause}")


#: Service error codes that mean "later, not never".
_RETRYABLE: dict[str, type[ApiError]] = {
    "tenant_not_initialized": VaultNotInitialized,
    "idempotency_in_progress": RequestInFlight,
    "storage_full": StorageFull,
    "quota_exceeded": QuotaExceeded,
}


def from_response(*, step: str, status: int, body: bytes | str) -> ApiError:
    """Build the right `ApiError` for a refusal.

    The body is whatever came back, and is not to be trusted to be JSON: the
    authorizer's denials are written by API Gateway, and a gateway timeout is
    written by nothing that has heard of this service at all.
    """
    code, detail = _read_body(body)

    cls = _RETRYABLE.get(code or "")
    if cls is None:
        cls = AuthError if status in (401, 403) else ApiError
    return cls(step=step, status=status, code=code, detail=detail)


def _read_body(body: bytes | str) -> tuple[str | None, str | None]:
    """`(code, detail)` out of an error body, for the several shapes it takes.

    Datavalv writes `{"code": ..., "detail": ...}`. API Gateway writes
    `{"message": "Forbidden"}` for an authorizer denial, which has no code at
    all. Anything else — HTML from a proxy, an empty body — reaches an operator
    as a trimmed excerpt rather than as nothing, because "403" alone does not
    say who said it.
    """
    text = body.decode(errors="replace") if isinstance(body, bytes) else body
    text = text.strip()
    if not text:
        return None, None

    try:
        parsed = json.loads(text)
    except ValueError:
        return None, _excerpt(text)

    if not isinstance(parsed, dict):
        return None, _excerpt(text)

    code = parsed.get("code")
    detail = parsed.get("detail") or parsed.get("message")
    return (
        code if isinstance(code, str) else None,
        detail if isinstance(detail, str) else None,
    )


def _excerpt(text: str, limit: int = 200) -> str:
    collapsed = " ".join(text.split())
    return collapsed if len(collapsed) <= limit else collapsed[: limit - 1] + "…"
