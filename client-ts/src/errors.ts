/**
 * What this client throws, and what an operator is told when it does.
 *
 * The same names, the same steps and the same `retryable` flag as
 * `client/src/datavalv_client/errors.py`. That is deliberate: an operator who
 * has read one of these two clients' failures should recognise the other's, and
 * a schedule that branches on `exc.retryable` in Python should branch on
 * `error.retryable` here and mean the same thing.
 *
 * The distinction the module exists to draw is **retryable or not**. A vault
 * whose owner has not signed in yet answers `409 tenant_not_initialized` to the
 * first two calls, and that is the service working correctly — there is no key
 * to encrypt against until a member's browser makes one. A schedule that treats
 * it as a fault sends somebody looking for a broken server on the evening a
 * customer simply has not logged in yet.
 */

/**
 * The steps, spelled once. They appear in every error message, so an operator
 * reading a failure and an operator reading the log are reading the same four
 * names — and the same four the Python client prints.
 *
 * The numbering is the ordering constraint stated out loud. Three of four
 * leaves a `pending` row and an object nothing will ever mark available, so a
 * message that says which of the four stopped is the difference between knowing
 * that and guessing.
 */
export const STEP_PUBLIC_KEY = "step 1 of 4, fetch the vault's public key";
export const STEP_REGISTER = "step 2 of 4, register the copy";
export const STEP_UPLOAD = "step 3 of 4, upload the encrypted copy";
export const STEP_COMPLETE = "step 4 of 4, confirm the upload";
export const STEP_CREATE_VAULT = "create the vault";
export const STEP_SET_RETENTION = "change how many copies the vault keeps";
export const STEP_DELETE_VAULT = "delete the vault";
export const STEP_LIST = "list the copies";

/** Base for everything this package throws deliberately. */
export class DatavalvError extends Error {
  /**
   * Whether running the same command again later could succeed with nothing
   * changed on the source server. False for anything an operator must fix.
   */
  readonly retryable: boolean = false;

  constructor(message: string) {
    super(message);
    this.name = new.target.name;
  }
}

/**
 * A missing or unusable setting: no API base, no client id, no key.
 *
 * Thrown before any request is made, so nothing has happened yet when an
 * operator reads it.
 */
export class ConfigurationError extends DatavalvError {}

/**
 * The service offered a key for this vault that is not the one on record.
 *
 * Thrown after step 1 and before anything is encrypted, so nothing has been
 * sent. **Not retryable, and never resolved by this client on its own**: a
 * vault's key is made once and does not change, so a different one is either a
 * vault that was deleted and created again -- a new vault, with a new key -- or
 * somebody answering for the service with a key they can open. Only a person
 * can tell which, by comparing `offered` with the fingerprint the vault's owner
 * sees under their backups.
 */
export class VaultKeyChanged extends DatavalvError {
  readonly externalId: string;
  readonly pinned: string;
  readonly offered: string;

  constructor(init: { externalId: string; pinned: string; offered: string; where: string }) {
    super(
      `the key offered for vault ${init.externalId} is not the one this machine has seen ` +
        "before. Nothing was encrypted or sent.\n" +
        `  on record: ${init.pinned}\n` +
        `  offered:   ${init.offered}\n` +
        "A vault's key never changes. If the vault was deleted and created again, ask its " +
        "owner for the fingerprint shown under their backups; if it is the offered one, " +
        `forget the old key (${init.where}) and push again. If it is not, do not push, ` +
        "and tell us.",
    );
    this.externalId = init.externalId;
    this.pinned = init.pinned;
    this.offered = init.offered;
  }
}

export interface ApiErrorInit {
  step: string;
  status: number;
  code?: string | undefined;
  detail?: string | undefined;
}

/**
 * A refusal from the Datavalv API, with the step it refused.
 *
 * `code` is the service's own error code where the body carried one. A denial
 * from the authorizer does not: API Gateway answers those itself, with its own
 * body, so `code` is then `undefined` and `status` is the whole of what is
 * known.
 */
export class ApiError extends DatavalvError {
  readonly step: string;
  readonly status: number;
  readonly code: string | undefined;
  readonly detail: string | undefined;

  /** Appended to the message by subclasses that know what to do about it. */
  static readonly advice: string | undefined = undefined;

  constructor(init: ApiErrorInit) {
    const advice = (new.target as typeof ApiError).advice;
    const named = init.code ?? `HTTP ${init.status}`;
    let message = `${init.step}: ${init.status} ${named}`;
    if (init.detail) message += ` — ${init.detail}`;
    if (advice) message += `\n${advice}`;
    super(message);
    this.step = init.step;
    this.status = init.status;
    this.code = init.code;
    this.detail = init.detail;
  }
}

/**
 * The token was refused: 401 or 403.
 *
 * Not retryable, and the distinction matters because the commonest cause is a
 * settings mistake rather than a broken key — a `clientId` from one
 * registration beside a `kid` from another, or a key retired in
 * `/applications` while the server still signs with it.
 */
export class AuthError extends ApiError {
  static override readonly advice =
    "The signing key, the client id or the key id is not what this vault's " +
    "registration holds. Check them against /applications, and that the key " +
    "there has not been retired.";
}

/**
 * `409 tenant_not_initialized`. Expected, and worth waiting out.
 *
 * The tenant key is generated in the first member's browser, so between
 * creating a vault and its owner signing in there is genuinely nothing to
 * encrypt against. Both `GET .../public-key` and `POST .../backups` answer
 * this, and both mean the same thing.
 */
export class VaultNotInitialized extends ApiError {
  override readonly retryable = true;
  static override readonly advice =
    "Nobody has started this vault yet: its key is made in the owner's " +
    "browser on their first sign-in, and until then there is nothing to " +
    "encrypt against. Nothing is broken and nothing on this server needs " +
    "changing — let the schedule run again.";
}

/**
 * `409 idempotency_in_progress`. The first attempt is still running.
 *
 * Reached by the thing this client sends an `Idempotency-Key` for in the first
 * place: a request that timed out on the wire and is being tried again while
 * the original is still working. Retryable, and quickly — the answer the caller
 * wants is being computed as they read this.
 *
 * Treating it as fatal would be worse than having no idempotency key at all: it
 * abandons a backup that is at that moment succeeding.
 */
export class RequestInFlight extends ApiError {
  override readonly retryable = true;
  static override readonly advice =
    "An earlier attempt with this idempotency key has not finished yet. " +
    "Wait a few seconds and send the same request again — it will be " +
    "answered with the first attempt's result rather than repeating the work.";
}

/**
 * `409 storage_full`. The upload completed and was refused for space.
 *
 * Distinct from `quota_exceeded`, which refuses before an upload URL is
 * issued. This one is only reachable when another push finished in between:
 * the bytes were sent, the server declined to store them, and it deleted them.
 * Nothing of yours was touched — the refusal happens before retention pruning,
 * so the backups you already had are exactly where they were.
 *
 * Retryable, and the whole push must be repeated rather than the upload
 * retried: the blob is gone and its upload URL names an object that no longer
 * exists.
 */
export class StorageFull extends ApiError {
  override readonly retryable = true;
  static override readonly advice =
    "The vault filled up between declaring this backup and finishing it, so " +
    "it was not stored and the uploaded copy was discarded. Nothing already " +
    "in the vault was affected. Run the push again; if it keeps happening, " +
    "the vault needs a larger allowance.";
}

/** `429 quota_exceeded`. Retryable in the sense that time may fix it. */
export class QuotaExceeded extends ApiError {
  override readonly retryable = true;
  static override readonly advice =
    "The account's quota is spent. A later run may succeed; see /pricing.";
}

/**
 * The `PUT` to storage failed.
 *
 * Separate from `ApiError` because the responder is S3, not Datavalv: the
 * status codes are S3's, the body is XML, and no Datavalv error code exists for
 * any of it. The two causes worth naming are in the message.
 */
export class UploadError extends DatavalvError {
  readonly status: number;
  readonly body: string;
  readonly step: string;

  constructor(init: { status: number; body?: string; step?: string }) {
    const step = init.step ?? STEP_UPLOAD;
    let message = `${step}: storage answered ${init.status}`;
    if (init.body) message += ` — ${init.body}`;
    if (init.status === 403) {
      message +=
        "\nA 403 here is usually an expired upload link (they last 15 " +
        "minutes) or a body that does not match the size and checksum " +
        "signed into it.";
    }
    super(message);
    this.status = init.status;
    this.body = init.body ?? "";
    this.step = step;
  }
}

/**
 * The request never got an answer: DNS, TCP, TLS, or a timeout.
 *
 * Retryable, and said so rather than left to inference. A nightly push that
 * lost its network is not a misconfigured server, and the message carries the
 * step so that "it never reached us" and "it reached us and was refused" do not
 * look alike in a log.
 */
export class NetworkError extends DatavalvError {
  override readonly retryable = true;
  readonly step: string;
  override readonly cause: unknown;

  constructor(init: { step: string; cause: unknown }) {
    const name = init.cause instanceof Error ? init.cause.name : "Error";
    const detail = init.cause instanceof Error ? init.cause.message : String(init.cause);
    super(`${init.step}: ${name}: ${detail}`);
    this.step = init.step;
    this.cause = init.cause;
  }
}

/** Service error codes that mean "later, not never". */
const RETRYABLE: Record<string, new (init: ApiErrorInit) => ApiError> = {
  tenant_not_initialized: VaultNotInitialized,
  idempotency_in_progress: RequestInFlight,
  storage_full: StorageFull,
  quota_exceeded: QuotaExceeded,
};

/**
 * Build the right `ApiError` for a refusal.
 *
 * The body is whatever came back, and is not to be trusted to be JSON: the
 * authorizer's denials are written by API Gateway, and a gateway timeout is
 * written by nothing that has heard of this service at all.
 */
export function fromResponse(init: { step: string; status: number; body: string }): ApiError {
  const { code, detail } = readBody(init.body);
  const Cls = (code ? RETRYABLE[code] : undefined) ?? (isAuthStatus(init.status) ? AuthError : ApiError);
  return new Cls({ step: init.step, status: init.status, code, detail });
}

function isAuthStatus(status: number): boolean {
  return status === 401 || status === 403;
}

/**
 * `{code, detail}` out of an error body, for the several shapes it takes.
 *
 * Datavalv writes `{"code": ..., "detail": ...}`. API Gateway writes
 * `{"message": "Forbidden"}` for an authorizer denial, which has no code at
 * all. Anything else — HTML from a proxy, an empty body — reaches an operator
 * as a trimmed excerpt rather than as nothing, because "403" alone does not say
 * who said it.
 */
function readBody(body: string): { code: string | undefined; detail: string | undefined } {
  const text = body.trim();
  if (!text) return { code: undefined, detail: undefined };

  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return { code: undefined, detail: excerpt(text) };
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    return { code: undefined, detail: excerpt(text) };
  }

  const record = parsed as Record<string, unknown>;
  const code = typeof record["code"] === "string" ? record["code"] : undefined;
  const detailValue = record["detail"] ?? record["message"];
  const detail = typeof detailValue === "string" ? detailValue : undefined;
  return { code, detail };
}

function excerpt(text: string, limit = 200): string {
  const collapsed = text.split(/\s+/).filter(Boolean).join(" ");
  return collapsed.length <= limit ? collapsed : `${collapsed.slice(0, limit - 1)}…`;
}
