/**
 * A fake Datavalv, close enough to the real one to catch the real mistakes.
 *
 * It stands in for `fetch`, so the client under test builds and sends genuine
 * requests — headers, bodies and all — and nothing here is a stand-in for the
 * code being tested. It is the same double as the Python client's
 * `tests/conftest.py`, down to the four rules it mirrors from
 * `api/src/datavalv_api/`, each of which a client can get wrong in a way a
 * lazier double would not notice:
 *
 * * every Datavalv call needs a bearer token, and the token is **verified** —
 *   signature, `aud`, `iss`, the five required claims, and the 300-second cap
 *   on `exp - iat` that `authorizer.verify` applies to the issued lifetime;
 * * a `jti` is accepted **once**, which is what makes a hoisted `Authorization`
 *   header fail here exactly as it would against the deployed authorizer;
 * * the presigned `PUT` goes to storage, which knows nothing of Datavalv tokens
 *   and refuses a request that carries a second set of credentials; and
 * * that `PUT` must carry `x-amz-checksum-sha256`, because
 *   `objects.presigned_put` signs `ChecksumSHA256` into the URL and S3 rejects
 *   a request that omits a signed header.
 */

import { createHash } from "node:crypto";
import { decodeProtectedHeader, importSPKI, jwtVerify } from "jose";

export const CLIENT_ID = "9fd31abd-e7ac-4d06-97c9-f9125f829bc4";
export const KEY_ID = "3783178c-9fe3-4a1c-aba5-6a4ee9478a5c";
export const TENANT_KEY_ID = "0f1c0a2b-8d5e-4a77-9c31-2b6d4e8f10aa";
export const EXTERNAL_ID = "kund-4711";
export const BACKUP_ID = "bk_01J8Z6QK9T";
export const UPLOAD_URL =
  "https://datavalv-staging.s3.eu-north-1.amazonaws.com/tenants/t1/bk.dvlv?sig=x";
export const API_BASE = "https://api-staging.datavalv.se";

/**
 * The authorizer's own cap on `exp - iat`, restated so the tests assert against
 * the rule rather than against this client's choice of lifetime.
 */
export const MAX_ISSUED_LIFETIME = 300;

/** The four steps, in the only order in which a backup exists at the end. */
export const FOUR_CALLS = [
  `GET /v1/tenants/${EXTERNAL_ID}/public-key`,
  `POST /v1/tenants/${EXTERNAL_ID}/backups`,
  "PUT upload",
  `POST /v1/backups/${BACKUP_ID}/complete`,
];

export class Call {
  constructor(
    readonly method: string,
    readonly url: URL,
    readonly headers: Map<string, string>,
    readonly content: Uint8Array,
  ) {}

  /**
   * A short name for the protocol step, for order assertions.
   *
   * The upload is told apart by its path rather than its host: everything
   * Datavalv answers is under `/v1/`, and the presigned URL is a bucket key.
   */
  get step(): string {
    if (!this.url.pathname.startsWith("/v1/")) return "PUT upload";
    return `${this.method} ${this.url.pathname}`;
  }

  json(): Record<string, unknown> {
    return JSON.parse(Buffer.from(this.content).toString("utf8")) as Record<string, unknown>;
  }

  get token(): string | undefined {
    const header = this.headers.get("authorization");
    if (!header) return undefined;
    if (!header.startsWith("Bearer ")) throw new Error(`not a bearer token: ${header}`);
    return header.slice("Bearer ".length);
  }
}

export interface FakeOptions {
  signingPublicPem: string;
  tenantPublicPem: string;
}

export class FakeDatavalv {
  /**
   * `failAt` names a step by its `Call.step` spelling; the first request
   * matching it is answered with `failure` instead of the happy path. That is
   * how the ordering tests break one link and check that nothing after it ran.
   */
  failAt: string | undefined;
  failure: { status: number; body: string } = {
    status: 500,
    body: '{"code":"internal_error"}',
  };

  readonly calls: Call[] = [];
  readonly seenJtis = new Set<string>();
  uploaded: Uint8Array | undefined;

  readonly #signingPublicPem: string;
  /** Mutable, so a test can have the service start offering a different key. */
  tenantPublicPem: string;

  constructor(options: FakeOptions) {
    this.#signingPublicPem = options.signingPublicPem;
    this.tenantPublicPem = options.tenantPublicPem;
  }

  /** Pass this where the client expects `fetch`. */
  readonly fetch: typeof globalThis.fetch = async (input, init) => {
    const call = new Call(
      init?.method ?? "GET",
      new URL(String(input)),
      lowercased(init?.headers),
      toBytes(init?.body),
    );
    this.calls.push(call);

    if (call.step === this.failAt) {
      return new Response(this.failure.body, { status: this.failure.status });
    }
    if (call.step === "PUT upload") return this.#upload(call);

    const denial = await this.#verify(call);
    if (denial) return denial;
    return this.#route(call);
  };

  // -- the authorizer, in miniature -------------------------------------

  async #verify(call: Call): Promise<Response | undefined> {
    const token = call.token;
    if (token === undefined) {
      // What API Gateway answers when there is no Authorization header at all.
      // The body is its own, not Datavalv's error shape.
      return json(401, { message: "Unauthorized" });
    }

    if (decodeProtectedHeader(token).kid !== KEY_ID) return json(403, { message: "Forbidden" });

    let claims: Record<string, unknown>;
    try {
      const key = await importSPKI(this.#signingPublicPem, "RS256");
      const verified = await jwtVerify(token, key, {
        audience: "datavalv",
        issuer: CLIENT_ID,
        requiredClaims: ["exp", "iat", "iss", "aud", "jti"],
      });
      claims = verified.payload as Record<string, unknown>;
    } catch {
      return json(403, { message: "Forbidden" });
    }

    if (Number(claims["exp"]) - Number(claims["iat"]) > MAX_ISSUED_LIFETIME) {
      return json(403, { message: "Forbidden" });
    }

    const jti = String(claims["jti"]);
    if (this.seenJtis.has(jti)) {
      // The single-use rule. `store.record_jti` raises `TokenReplayed`, the
      // authorizer denies, and `enable_simple_responses` turns the denial into
      // a 403.
      return json(403, { message: "Forbidden" });
    }
    this.seenJtis.add(jti);
    return undefined;
  }

  // -- routing -----------------------------------------------------------

  #upload(call: Call): Response {
    if (call.headers.get("authorization")) {
      // S3 refuses a presigned request that also carries an Authorization
      // header: two sets of credentials on one request.
      return new Response(
        "<Error><Code>InvalidArgument</Code><Message>Only one auth mechanism " +
          "allowed</Message></Error>",
        { status: 400 },
      );
    }
    const checksum = call.headers.get("x-amz-checksum-sha256");
    if (!checksum) {
      // The URL signs ChecksumSHA256, so the header is required rather than
      // merely accepted.
      return new Response("<Error><Code>SignatureDoesNotMatch</Code></Error>", { status: 403 });
    }
    const digest = createHash("sha256").update(call.content).digest();
    if (!digest.equals(Buffer.from(checksum, "base64"))) {
      return new Response("<Error><Code>BadDigest</Code></Error>", { status: 400 });
    }
    this.uploaded = call.content;
    return new Response(null, { status: 200, headers: { "x-amz-checksum-sha256": checksum } });
  }

  #route(call: Call): Response {
    const path = call.url.pathname;
    const method = call.method;

    if (method === "GET" && path === `/v1/tenants/${EXTERNAL_ID}/public-key`) {
      return json(200, {
        tenantId: "t-1",
        keyId: TENANT_KEY_ID,
        publicKeyPem: this.tenantPublicPem,
      });
    }
    if (method === "POST" && path === `/v1/tenants/${EXTERNAL_ID}/backups`) {
      return json(201, { backupId: BACKUP_ID, uploadUrl: UPLOAD_URL, expiresIn: 900 });
    }
    if (method === "POST" && path === `/v1/backups/${BACKUP_ID}/complete`) {
      return json(200, { status: "available", pruned: 0 });
    }
    if (method === "POST" && path === "/v1/tenants") {
      return json(201, { tenantId: "t-1", status: "provisioned" });
    }
    if (method === "PATCH" && path === `/v1/tenants/${EXTERNAL_ID}`) {
      return json(200, { status: "ok" });
    }
    if (method === "DELETE" && path === `/v1/tenants/${EXTERNAL_ID}`) {
      return json(200, { tenantId: "t-1", status: "deleted" });
    }
    if (method === "GET" && path === `/v1/tenants/${EXTERNAL_ID}/backups`) {
      return json(200, { backups: [] });
    }

    return json(404, { code: "not_found", detail: path });
  }
}

/**
 * `fetch`'s own second argument, taken from the global rather than named as
 * `RequestInit`: the DOM lib is deliberately not loaded here, and the shape
 * this fake must read is whatever the runtime's `fetch` accepts.
 */
type FetchInit = NonNullable<Parameters<typeof globalThis.fetch>[1]>;

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function lowercased(headers: FetchInit["headers"]): Map<string, string> {
  const map = new Map<string, string>();
  if (!headers) return map;
  const entries = headers instanceof Headers ? headers.entries() : Object.entries(headers);
  for (const [name, value] of entries as Iterable<[string, string]>) {
    map.set(name.toLowerCase(), String(value));
  }
  return map;
}

function toBytes(body: FetchInit["body"]): Uint8Array {
  if (body === null || body === undefined) return new Uint8Array(0);
  if (typeof body === "string") return new Uint8Array(Buffer.from(body, "utf8"));
  if (body instanceof Uint8Array) return body;
  throw new TypeError(`the fake does not know how to read a ${typeof body} body`);
}
