/**
 * The HTTP layer: four calls, in one order, with one token each.
 *
 * `api/src/datavalv_api/` is the authority for all of it, and
 * `client/src/datavalv_client/client.py` is the same protocol in Python. This
 * module is a second implementation, not a second design: same order, same
 * fields, same error classes, same meaning for each.
 *
 * One backup costs four calls:
 *
 * 1. `GET  /v1/tenants/{externalId}/public-key` → `keyId`, `publicKeyPem`
 * 2. `POST /v1/tenants/{externalId}/backups` → `backupId`, `uploadUrl`
 * 3. `PUT  {uploadUrl}` — the ciphertext, with `x-amz-checksum-sha256`
 * 4. `POST /v1/backups/{backupId}/complete`
 *
 * Three details are load-bearing and none of them is visible from the call
 * list:
 *
 * * **A token is spent on arrival.** `authorizer.verify` records every `jti`
 *   and the authorizer's result is cached for zero seconds, so each of the
 *   three Datavalv calls mints its own. See `tokens.ts`.
 * * **The digest is of the ciphertext**, never the plaintext, and it travels
 *   twice in two spellings: hex in the JSON body, base64 of the same bytes in
 *   the S3 header. `push` computes it once and encodes it twice, which is the
 *   only arrangement in which the two cannot disagree.
 * * **The `PUT` carries no `Authorization`.** The URL is presigned; an
 *   `Authorization` header alongside it is a second set of credentials on one
 *   request, and S3 refuses that. It is also the one call that does not go to
 *   Datavalv at all.
 *
 * A backup exists for the service only after step 4. Three of four leaves a
 * `pending` row and an object that no reader will ever be offered — which is
 * why `pushBackup` is one method rather than four, and why a failure anywhere
 * in it throws rather than returning something partial.
 */

import { createHash, type KeyObject } from "node:crypto";

import {
  decodeHeader,
  encrypt,
  generateDek,
  publicKeyFingerprint,
  wrapDek,
} from "@datavalv/crypto";

import {
  ConfigurationError,
  NetworkError,
  STEP_COMPLETE,
  STEP_CREATE_VAULT,
  STEP_DELETE_VAULT,
  STEP_SET_RETENTION,
  STEP_LIST,
  STEP_PUBLIC_KEY,
  STEP_REGISTER,
  STEP_UPLOAD,
  UploadError,
  VaultKeyChanged,
  fromResponse,
} from "./errors.js";
import { FilePins, type KeyPins } from "./pins.js";
import { authorizationHeader, loadSigningKey } from "./tokens.js";

/**
 * Generous on the upload, bounded on everything else.
 *
 * The upload is the one call whose body can be gigabytes, and a deadline sized
 * for a JSON request would kill a large backup part-way — leaving exactly the
 * three-of-four state step 4 exists to prevent.
 *
 * Unlike httpx's per-operation timeouts in the Python client, `AbortSignal`
 * bounds the *whole* call rather than the gap between bytes, so these are wall
 * clocks: fifteen minutes is also the life of a presigned URL, and an upload
 * still running after that would be refused by S3 anyway.
 */
export const DEFAULT_TIMEOUT_MS = 60_000;
export const DEFAULT_UPLOAD_TIMEOUT_MS = 900_000;

/**
 * The `label` cap from `models.CreateBackupRequest`, checked here so that a
 * too-long note fails before the file has been encrypted and uploaded rather
 * than as a `422` on step 2.
 */
export const MAX_LABEL_LENGTH = 200;

/**
 * The `nameCipherB64` cap from `models.NameCipherB64`, in base64 characters.
 * 512 of them hold 347 bytes of UTF-8 filename once the 37 bytes of format
 * overhead are paid, comfortably above any filename a source server can have
 * opened — so this is a guard against a caller passing something that is not a
 * filename, not a limit a real push meets.
 */
export const MAX_NAME_CIPHER_B64 = 512;

/**
 * What a completed push produced.
 *
 * `sha256` is the ciphertext's digest, hex — the same value the service stored
 * and the same one it verified against S3 before marking the backup available.
 */
export interface PushedBackup {
  backupId: string;
  size: number;
  sha256: string;
  keyId: string;
  pruned: number;
  /**
   * The fingerprint of the key this copy was encrypted to -- the string the
   * vault's owner is shown under their backups.
   */
  keyFingerprint: string;
  /**
   * Whether this push was the first time this machine saw that key. The one
   * moment the fingerprint is worth reading out to somebody: compared once
   * with the owner's, the pin is the vault's key and not merely the first key
   * this machine was told about.
   */
  keyFirstSeen: boolean;
  /**
   * Whether this copy was pushed with `keep`: retention never removes it, and
   * only a vault member can delete it or hand it back to retention.
   */
  kept: boolean;
}

export interface CreatedVault {
  tenantId: string;
  status: string;
}

export interface DeletedVault {
  tenantId: string;
  status: string;
}

export interface TenantPublicKey {
  tenantId?: string;
  keyId: string;
  publicKeyPem: string;
}

export interface CreatedBackup {
  backupId: string;
  uploadUrl: string;
  expiresIn?: number;
}

export interface DatavalvClientOptions {
  apiBase: string;
  clientId: string;
  keyId: string;
  /**
   * PEM **text** or an already-loaded `KeyObject` — never a path, which is the
   * opposite of `DATAVALV_PRIVATE_KEY`'s rule and for the same reason. See
   * `loadPrivateKey`.
   */
  privateKey: string | KeyObject;
  /** The injection seam the tests drive. Nothing on the command line reaches it. */
  fetch?: typeof globalThis.fetch;
  timeoutMs?: number;
  uploadTimeoutMs?: number;
  /**
   * Where each vault's key fingerprint is remembered so that a changed key is
   * refused (`pins.ts`). Left out, it is `FilePins.default()` -- a file in the
   * user's state directory, or wherever `DATAVALV_KNOWN_VAULTS` points --
   * because the protection has to hold across processes to mean anything for a
   * scheduled job, and a default that remembered nothing would be a default
   * that protected nothing. Pass `new MemoryPins([...])` with fingerprints from
   * configuration on a machine that has no disk to remember on.
   */
  pins?: KeyPins;
}

/**
 * A signing key from PEM text, or a key object straight through.
 *
 * **A path is refused, loudly.** `DATAVALV_PRIVATE_KEY` names a file for a
 * reason — a private key in an environment variable is in `ps`, in the shell
 * history that set it and in every crash dump of the process — and a caller who
 * passes the path here has made the near-miss of that mistake. Reading the file
 * for them would be convenient and would make the two spellings
 * interchangeable, which is how the variable ends up holding the key.
 */
/**
 * The shapes a private key really arrives in, matched against every JSON body
 * before it is sent.
 *
 * **Nothing this library sends has a field for a key.** The signing key is
 * read from a file and used to sign; every value a caller fills in is a name,
 * a label, a digest or a wrapped DEK. So a private key in one of them is a
 * paste that went into the wrong argument, and the only useful moment to
 * notice is before the request: afterwards it has been in somebody else's
 * logs whatever anybody does about it next.
 *
 * A *block*, not the words -- "nightly private key backup" is a label
 * somebody will legitimately write. `[^-]*` between BEGIN and PRIVATE KEY
 * carries the labels: plain, RSA, EC, ENCRYPTED, OPENSSH, PGP. PuTTY's own
 * format has no BEGIN line at all and is matched by its header.
 *
 * The same shapes `client.py` refuses on the Python side and
 * `web/src/app/pages/applications/applications.ts` refuses in the browser.
 */
const PRIVATE_KEY_SHAPES = [
  /-{3,}\s*BEGIN[^-]*PRIVATE KEY\s*-{3,}/i,
  /PuTTY-User-Key-File/i,
  /^Private-Lines:/im,
];

/** Throw before a request carrying a private key can be made. */
function refuseKeyMaterial(body: string | undefined): void {
  if (body === undefined) return;
  if (PRIVATE_KEY_SHAPES.some((shape) => shape.test(body))) {
    throw new ConfigurationError(
      "this request carries what looks like a private key, so nothing was sent. " +
        "Datavalv never needs one: the signing key stays on your server and is " +
        "used to sign, and no field here is for key material.",
    );
  }
}

function loadPrivateKey(privateKey: string | KeyObject): KeyObject {
  if (typeof privateKey !== "string") return privateKey;
  if (!privateKey.includes("-----BEGIN")) {
    throw new ConfigurationError(
      "privateKey must be PEM text or a loaded KeyObject; this looks like a " +
        "filename. Read the file and pass its contents — and keep the key " +
        "itself out of environment variables.",
    );
  }
  try {
    return loadSigningKey(privateKey);
  } catch (exc) {
    const detail = exc instanceof Error ? exc.message : String(exc);
    // The message, not the key: `createPrivateKey` reports what it could not
    // parse without repeating the PEM, and nothing here adds it back.
    throw new ConfigurationError(`privateKey is not a usable PEM key: ${detail}`);
  }
}

/** A source application's connection to Datavalv. */
export class DatavalvClient {
  readonly apiBase: string;
  readonly clientId: string;
  readonly keyId: string;

  readonly pins: KeyPins;

  readonly #privateKey: KeyObject;
  readonly #fetch: typeof globalThis.fetch;
  readonly #timeoutMs: number;
  readonly #uploadTimeoutMs: number;

  /**
   * `apiBase` may be given with or without the `/v1` suffix; both spellings are
   * in this project's own runbooks, so both are accepted and normalised here
   * rather than producing a `404` whose cause is a doubled path segment.
   */
  constructor(options: DatavalvClientOptions) {
    if (!options.apiBase) {
      throw new ConfigurationError("apiBase is required, e.g. https://api.datavalv.se");
    }
    if (!options.clientId) {
      throw new ConfigurationError("clientId is required; it is what /applications issued");
    }
    if (!options.keyId) {
      throw new ConfigurationError("keyId is required; it is the kid of the registered key");
    }

    this.apiBase = options.apiBase.replace(/\/+$/, "").replace(/\/v1$/, "");
    this.clientId = options.clientId;
    this.keyId = options.keyId;
    this.#privateKey = loadPrivateKey(options.privateKey);
    this.pins = options.pins ?? FilePins.default();
    // Bound to `globalThis`: undici's `fetch` throws "Illegal invocation" if it
    // is called with any other receiver, which is what storing it as a property
    // and calling `this.#fetch(...)` would do.
    this.#fetch = options.fetch ?? globalThis.fetch.bind(globalThis);
    this.#timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.#uploadTimeoutMs = options.uploadTimeoutMs ?? DEFAULT_UPLOAD_TIMEOUT_MS;
  }

  // -- the calls ---------------------------------------------------------

  /** One header, one request. Never hoisted — see `tokens.ts`. */
  async #auth(): Promise<Record<string, string>> {
    return authorizationHeader({
      clientId: this.clientId,
      keyId: this.keyId,
      privateKey: this.#privateKey,
    });
  }

  async #call(
    method: string,
    path: string,
    options: { step: string; json?: unknown; headers?: Record<string, string> },
  ): Promise<unknown> {
    const headers: Record<string, string> = { ...(await this.#auth()), ...options.headers };
    let body: string | undefined;
    if (options.json !== undefined) {
      body = JSON.stringify(options.json);
      // Before the token is even spent: a body that carries key material is
      // a mistake to stop, not to report afterwards.
      refuseKeyMaterial(body);
      headers["content-type"] = "application/json";
    }

    let response: Response;
    try {
      response = await this.#fetch(`${this.apiBase}${path}`, {
        method,
        headers,
        ...(body === undefined ? {} : { body }),
        redirect: "manual",
        signal: AbortSignal.timeout(this.#timeoutMs),
      });
    } catch (exc) {
      throw new NetworkError({ step: options.step, cause: exc });
    }

    if (response.status >= 400) {
      throw fromResponse({
        step: options.step,
        status: response.status,
        body: await response.text(),
      });
    }
    return response.json();
  }

  /**
   * Step 1: the vault's public key, and the id of the key it is.
   *
   * `409 tenant_not_initialized` here is `VaultNotInitialized`, which reports
   * itself retryable: the vault's key is made in the first member's browser, so
   * before that first sign-in there is nothing to fetch.
   */
  async tenantPublicKey(externalId: string): Promise<TenantPublicKey> {
    return (await this.#call("GET", `/v1/tenants/${externalId}/public-key`, {
      step: STEP_PUBLIC_KEY,
    })) as TenantPublicKey;
  }

  /**
   * Step 2: declare the copy and get somewhere to put it.
   *
   * `sha256Hex` is the digest of the **ciphertext**. The service signs it and
   * `size` into the presigned URL, so a body that disagrees with either is
   * refused by S3 itself rather than trusted and stored.
   *
   * `idempotencyKey` is worth sending from a schedule that retries a run that
   * timed out: without it a retry inside the window mints a second backup id,
   * consumes quota twice and stores the same night twice.
   */
  async createBackup(
    externalId: string,
    fields: {
      size: number;
      sha256Hex: string;
      wrappedDekB64: string;
      ivB64: string;
      keyId: string;
      label?: string | undefined;
      nameCipherB64?: string | undefined;
      keep?: boolean | undefined;
      idempotencyKey?: string | undefined;
    },
  ): Promise<CreatedBackup> {
    const body: Record<string, unknown> = {
      size: fields.size,
      sha256: fields.sha256Hex,
      wrappedDekB64: fields.wrappedDekB64,
      ivB64: fields.ivB64,
      keyId: fields.keyId,
    };
    // Omitted rather than sent as null: the request model forbids unknown
    // fields and applies its own defaults, and an explicit null is a 422 rather
    // than "use the default".
    if (fields.label !== undefined) body["label"] = fields.label;
    if (fields.nameCipherB64 !== undefined) body["nameCipherB64"] = fields.nameCipherB64;
    // Only when asked for, so an ordinary push sends the body it always did.
    if (fields.keep) body["keep"] = true;

    return (await this.#call("POST", `/v1/tenants/${externalId}/backups`, {
      step: STEP_REGISTER,
      json: body,
      ...(fields.idempotencyKey
        ? { headers: { "Idempotency-Key": fields.idempotencyKey } }
        : {}),
    })) as CreatedBackup;
  }

  /**
   * Step 3: the ciphertext, to the presigned URL, with the checksum.
   *
   * The header is **required, not optional**: `objects.presigned_put` signs
   * `ChecksumSHA256` into the URL, and S3 rejects a request that omits a signed
   * header. The value is base64 of the same bytes `sha256Hex` spells in hex —
   * which is why this takes the hex and converts, rather than taking a second
   * argument that could be a different digest.
   *
   * No `Authorization` header: the URL carries its own signature, and a second
   * set of credentials on the request is refused.
   */
  async uploadCiphertext(
    uploadUrl: string,
    blob: Uint8Array,
    options: { sha256Hex: string },
  ): Promise<void> {
    const checksumB64 = Buffer.from(options.sha256Hex, "hex").toString("base64");

    let response: Response;
    try {
      response = await this.#fetch(uploadUrl, {
        method: "PUT",
        // A `Uint8Array` body, not a stream: undici sets `Content-Length` from
        // it, and `presigned_put` signs `ContentLength` as well as the
        // checksum. A streamed body would go up chunked, with no length at all,
        // and S3 would answer 403 with nothing in it about why.
        body: blob,
        headers: { "x-amz-checksum-sha256": checksumB64 },
        signal: AbortSignal.timeout(this.#uploadTimeoutMs),
      });
    } catch (exc) {
      throw new NetworkError({ step: STEP_UPLOAD, cause: exc });
    }

    if (response.status >= 400) {
      throw new UploadError({ status: response.status, body: await response.text() });
    }
  }

  /**
   * Step 4: the service checks S3 itself, then the copy counts.
   *
   * Until this returns, the backup is `pending`: it is not listed as available,
   * and retention has not pruned anything — so the previous good copy is still
   * there. That ordering is the product's central promise and is
   * `routes_backups.complete_backup`'s doing, not this client's.
   */
  async completeBackup(backupId: string): Promise<Record<string, unknown>> {
    return (await this.#call("POST", `/v1/backups/${backupId}/complete`, {
      step: STEP_COMPLETE,
    })) as Record<string, unknown>;
  }

  // -- vaults ------------------------------------------------------------

  /**
   * One vault, for one customer whose copies this server will push.
   *
   * `ownerEmail` is the whole of the connection between a vault and the person
   * who will own it: there is no invitation link and no code, and the vault
   * appears only to a signed-in account whose *confirmed* address is identical
   * to this one. A typo here succeeds, mails nobody who will read it, and is
   * reported as an error to no one. Read it back to the customer before
   * calling.
   *
   * `locale` is supplied, never detected — no browser is involved in this call,
   * so nothing on the path can observe what the owner reads. Omitted, the
   * bootstrap invitation is written in Swedish.
   */
  async createVault(
    externalId: string,
    ownerEmail: string,
    options: {
      name?: string | undefined;
      locale?: "sv" | "en" | undefined;
      retentionCount?: number | undefined;
    } = {},
  ): Promise<CreatedVault> {
    const body: Record<string, unknown> = { externalId, ownerEmail };
    if (options.name !== undefined) body["name"] = options.name;
    if (options.locale !== undefined) body["locale"] = options.locale;
    if (options.retentionCount !== undefined) body["retentionCount"] = options.retentionCount;

    const payload = (await this.#call("POST", "/v1/tenants", {
      step: STEP_CREATE_VAULT,
      json: body,
    })) as { tenantId: string; status: string };
    return { tenantId: payload.tenantId, status: payload.status };
  }

  /**
   * End a vault: its rows, its objects, and its identifier.
   *
   * The most destructive call this client can make. It drops the member rows,
   * the backup rows and the pointer, then the service enqueues a purge that
   * deletes the objects from storage. Nothing here is recoverable, and the
   * identifier is freed for reuse.
   *
   * **`confirm` is required and is checked before anything is sent.** The API
   * asks for the identifier twice — once in the path and once in the body —
   * precisely so that one wrong variable cannot end a customer's vault, and a
   * client that defaulted `confirm` to `externalId` would be the one
   * implementation of that guard which cannot fail. So this asks the caller
   * for it, and refuses a mismatch here rather than spending a signed call to
   * be told `confirmation_mismatch`.
   */
  async deleteVault(
    externalId: string,
    options: { confirm: string },
  ): Promise<DeletedVault> {
    if (options.confirm !== externalId) {
      throw new ConfigurationError(
        `confirm must repeat the vault's identifier: expected ${externalId}, ` +
          `got ${options.confirm}`,
      );
    }

    const payload = (await this.#call("DELETE", `/v1/tenants/${externalId}`, {
      step: STEP_DELETE_VAULT,
      json: { confirm: options.confirm },
    })) as { tenantId: string; status: string };
    return { tenantId: payload.tenantId, status: payload.status };
  }

  /**
   * How many copies this vault keeps, changed for a vault that exists.
   *
   * Retention is settable at creation and changeable for the life of the
   * vault, and until this method the second half meant composing and signing
   * the call by hand — which is the part of this protocol a client exists to
   * do for you.
   *
   * **Nothing is deleted when this resolves.** Retention runs when the next
   * copy is confirmed, so lowering the number takes effect on the next push
   * rather than now; a vault that is never pushed to again keeps every copy
   * it has. `routes_backups.prune` is where that happens.
   *
   * The range is checked here rather than left to the `422`, because a signed
   * call and a round trip is a slow way to be told something this client
   * already knew.
   */
  async setRetention(externalId: string, retentionCount: number): Promise<void> {
    if (!Number.isInteger(retentionCount)) {
      throw new ConfigurationError(
        `retentionCount must be a whole number of copies, not ${retentionCount}`,
      );
    }
    if (retentionCount < 1 || retentionCount > 365) {
      throw new ConfigurationError(
        `retentionCount must be between 1 and 365, not ${retentionCount}`,
      );
    }

    await this.#call("PATCH", `/v1/tenants/${externalId}`, {
      step: STEP_SET_RETENTION,
      json: { retentionCount },
    });
  }

  /**
   * What the service holds for this vault.
   *
   * No key material comes back on this route — a source application pushes
   * copies and is never given the means to read one. That is `BackupSummary`
   * versus `MemberBackupSummary` in `models.py`, and it is deliberate.
   */
  async listBackups(externalId: string): Promise<Record<string, unknown>[]> {
    const payload = (await this.#call("GET", `/v1/tenants/${externalId}/backups`, {
      step: STEP_LIST,
    })) as { backups: Record<string, unknown>[] };
    return payload.backups;
  }

  // -- the whole sequence ------------------------------------------------

  /**
   * Encrypt, register, upload and confirm. All four, or an exception.
   *
   * `data` is bytes, already in memory: the size and the digest of the
   * *ciphertext* have to be known before step 2 can be called at all, so there
   * is no streaming arrangement that would not encrypt twice. A caller with a
   * file reads it first — `await readFile(path)`.
   *
   * `name` is the original filename. It is encrypted under the same DEK as the
   * payload and sent as `nameCipherB64`, so the member who can open the backup
   * can read what it was called and nobody else can — a name like
   * `medlemsregister-2026-09-30.sql` states what software a club runs, what the
   * data is and when it was taken. Pass the basename; a directory is nobody's
   * business either.
   */
  async pushBackup(
    externalId: string,
    data: Uint8Array,
    options: {
      name?: string | undefined;
      label?: string | undefined;
      keep?: boolean | undefined;
      idempotencyKey?: string | undefined;
    } = {},
  ): Promise<PushedBackup> {
    if (options.label !== undefined && options.label.length > MAX_LABEL_LENGTH) {
      throw new RangeError(
        `label is ${options.label.length} characters; the service caps it at ${MAX_LABEL_LENGTH}`,
      );
    }

    const key = await this.tenantPublicKey(externalId);
    const checked = await this.#checkKey(externalId, key.publicKeyPem);
    const pushed = await this.#push(externalId, data, key, options);
    return { ...pushed, keyFingerprint: checked.fingerprint, keyFirstSeen: checked.firstSeen };
  }

  /**
   * The fingerprint of the key just offered, and whether it is new here.
   *
   * **Between step 1 and everything else, and nowhere later.** Once a DEK has
   * been wrapped to a key, whoever holds that key's private half can open the
   * copy; a check after the upload would be a check after the fact. So a key
   * that is not the one on record throws here, before a byte is encrypted, and
   * the pin is left exactly as it was -- a client that re-pinned on a mismatch
   * would refuse once and then comply.
   *
   * The first key seen for a vault is recorded and reported as such. That is
   * trust on first use, and the caller is told so that a person can turn it
   * into more than that by comparing the fingerprint once.
   */
  async #checkKey(
    externalId: string,
    publicKeyPem: string,
  ): Promise<{ fingerprint: string; firstSeen: boolean }> {
    const offered = await publicKeyFingerprint(publicKeyPem);
    const pinned = this.pins.get(this.apiBase, this.clientId, externalId);
    if (pinned === undefined) {
      this.pins.set(this.apiBase, this.clientId, externalId, offered);
      return { fingerprint: offered, firstSeen: true };
    }
    if (pinned !== offered) {
      throw new VaultKeyChanged({
        externalId,
        pinned,
        offered,
        where: `\`datavalv vault key --external-id ${externalId} --forget\``,
      });
    }
    return { fingerprint: offered, firstSeen: false };
  }

  async #push(
    externalId: string,
    plaintext: Uint8Array,
    key: TenantPublicKey,
    options: {
      name?: string | undefined;
      label?: string | undefined;
      keep?: boolean | undefined;
      idempotencyKey?: string | undefined;
    },
  ): Promise<Omit<PushedBackup, "keyFingerprint" | "keyFirstSeen">> {
    const dek = await generateDek();
    const blob = await encrypt(bytes(plaintext), dek);
    // The IV is read back out of the header rather than generated here and
    // passed in. `encrypt` draws its own, and a second copy of that value in
    // this module is a second thing that can be wrong about what was actually
    // used to encrypt.
    const iv = decodeHeader(blob);
    const wrappedDek = await wrapDek(dek, key.publicKeyPem);

    // Computed once. The body carries it as hex and the S3 header as base64 of
    // the same bytes; two digests computed separately is the defect that passes
    // an assertion on either one alone.
    const digest = createHash("sha256").update(blob).digest();
    const sha256Hex = digest.toString("hex");

    let nameCipherB64: string | undefined;
    if (options.name) {
      // No IV argument: `encrypt` draws a fresh one per call, which is what
      // makes reusing the DEK for this second message safe. Passing the
      // payload's IV here would reuse a nonce under one AES-GCM key, which is
      // catastrophic rather than merely untidy.
      const sealed = await encrypt(bytes(Buffer.from(options.name, "utf8")), dek);
      nameCipherB64 = Buffer.from(sealed).toString("base64");
      if (nameCipherB64.length > MAX_NAME_CIPHER_B64) {
        throw new RangeError(
          `the encrypted name is ${nameCipherB64.length} base64 characters; the ` +
            `service caps nameCipherB64 at ${MAX_NAME_CIPHER_B64}. Pass a basename ` +
            "rather than a path.",
        );
      }
    }

    const created = await this.createBackup(externalId, {
      size: blob.length,
      sha256Hex,
      wrappedDekB64: Buffer.from(wrappedDek).toString("base64"),
      ivB64: Buffer.from(iv).toString("base64"),
      keyId: key.keyId,
      label: options.label,
      nameCipherB64,
      keep: options.keep,
      idempotencyKey: options.idempotencyKey,
    });

    await this.uploadCiphertext(created.uploadUrl, blob, { sha256Hex });
    const completed = await this.completeBackup(created.backupId);

    return {
      backupId: created.backupId,
      size: blob.length,
      sha256: sha256Hex,
      keyId: key.keyId,
      pruned: Number(completed["pruned"] ?? 0),
      kept: options.keep === true,
    };
  }
}

/**
 * A `Uint8Array` over a plain `ArrayBuffer`, which is what `@datavalv/crypto`'s
 * `Bytes` is. A `Buffer` is backed by a pooled `ArrayBuffer` slice and a
 * `SharedArrayBuffer` is not a `BufferSource` at all, so this copies only when
 * it must — the common case, a `Uint8Array` a caller already owns, is passed
 * straight through.
 */
function bytes(data: Uint8Array): Uint8Array<ArrayBuffer> {
  if (data.buffer instanceof ArrayBuffer && data.byteOffset === 0 && data.byteLength === data.buffer.byteLength) {
    return data as Uint8Array<ArrayBuffer>;
  }
  return new Uint8Array(data);
}
