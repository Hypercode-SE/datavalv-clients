/**
 * The four calls, the three tokens, and the one digest.
 *
 * Every assertion here was checked by breaking the code it covers and watching
 * it fail; where the break is not obvious from the assertion, the test says
 * what it was. That matters more than usual in this file: three of the things
 * it checks — the ordering, the token per call, and the two spellings of one
 * digest — are each satisfied by a plausible wrong implementation that a weaker
 * assertion passes.
 */

import { createHash } from "node:crypto";
import { describe, expect, test } from "vitest";
import { decodeProtectedHeader, importSPKI, jwtVerify } from "jose";

import { decodeHeader, decrypt, unwrapDek } from "@datavalv/crypto";

import { DatavalvClient } from "../src/client.js";
import {
  ApiError,
  AuthError,
  ConfigurationError,
  NetworkError,
  QuotaExceeded,
  RequestInFlight,
  StorageFull,
  UploadError,
  VaultNotInitialized,
} from "../src/errors.js";
import {
  API_BASE,
  BACKUP_ID,
  CLIENT_ID,
  EXTERNAL_ID,
  FOUR_CALLS,
  FakeDatavalv,
  KEY_ID,
  MAX_ISSUED_LIFETIME,
  TENANT_KEY_ID,
  UPLOAD_URL,
} from "./support/fakeDatavalv.js";
import { signingKey, tenantKey } from "./support/fixtures.js";

const PLAINTEXT = new Uint8Array(Buffer.from("-- a database dump, or near enough\n".repeat(64)));

/**
 * What the API really answers while a vault is waiting for its owner, detail
 * and all: `routes_backups.create_backup` raises `TenantNotInitialized` with
 * exactly this sentence.
 */
const DETAIL_409 =
  '{"code":"tenant_not_initialized","detail":"no member has generated the tenant key ' +
  'yet; retry after first login"}';

function service(): FakeDatavalv {
  return new FakeDatavalv({
    signingPublicPem: signingKey.publicKeyPem,
    tenantPublicPem: tenantKey.publicKeyPem,
  });
}

function makeClient(fake: FakeDatavalv, apiBase = API_BASE): DatavalvClient {
  return new DatavalvClient({
    apiBase,
    clientId: CLIENT_ID,
    keyId: KEY_ID,
    privateKey: signingKey.privateKeyPem,
    fetch: fake.fetch,
  });
}

function registered(fake: FakeDatavalv): Record<string, unknown> {
  return fake.calls.find((call) => call.step === FOUR_CALLS[1])!.json();
}

// ------------------------------------------------------------------ ordering

describe("ordering", () => {
  test("push makes the four calls in order", async () => {
    const fake = service();
    const pushed = await makeClient(fake).pushBackup(EXTERNAL_ID, PLAINTEXT, {
      name: "dump.sql.gz",
    });

    expect(fake.calls.map((call) => call.step)).toEqual(FOUR_CALLS);
    expect(pushed.backupId).toBe(BACKUP_ID);
    expect(pushed.sha256).toBe(createHash("sha256").update(fake.uploaded!).digest("hex"));
  });

  test.each([1, 2, 3, 4])(
    "a failure at step %i stops the ones after it",
    async (stopAfter) => {
      // Asserting only that pushBackup rejected would pass for a client that
      // made all four calls and reported the first failure at the end — which
      // is the failure mode that leaves an object uploaded against a backup row
      // the caller was told had failed.
      const fake = service();
      fake.failAt = FOUR_CALLS[stopAfter - 1];
      fake.failure = { status: 500, body: '{"code":"internal_error"}' };

      await expect(makeClient(fake).pushBackup(EXTERNAL_ID, PLAINTEXT)).rejects.toThrow();
      expect(fake.calls.map((call) => call.step)).toEqual(FOUR_CALLS.slice(0, stopAfter));
    },
  );

  test("nothing is uploaded when registering fails", async () => {
    const fake = service();
    fake.failAt = FOUR_CALLS[1];
    fake.failure = { status: 413, body: '{"code":"too_large","detail":"exceeds the cap"}' };

    await expect(makeClient(fake).pushBackup(EXTERNAL_ID, PLAINTEXT)).rejects.toBeInstanceOf(
      ApiError,
    );
    expect(fake.uploaded).toBeUndefined();
  });
});

// -------------------------------------------------------------------- tokens

describe("tokens", () => {
  test("each Datavalv call carries its own token, and each one verifies", async () => {
    // Three calls, three tokens, three `jti`s — and each one verifies.
    //
    // The fake authorizer records `jti`s and refuses a repeat, exactly as the
    // deployed one does, so hoisting the header into a variable turns this into
    // a 403 on the second call rather than a subtle assertion failure. Both
    // halves are asserted anyway: a client could mint three tokens sharing one
    // `jti`, which the uniqueness check catches, and a client could mint three
    // unverifiable tokens against a fake that did not check.
    const fake = service();
    await makeClient(fake).pushBackup(EXTERNAL_ID, PLAINTEXT);

    const tokens = fake.calls
      .map((call) => call.token)
      .filter((token): token is string => token !== undefined);
    expect(tokens, "the three Datavalv calls each need their own token").toHaveLength(3);
    expect(new Set(tokens).size).toBe(3);

    const key = await importSPKI(signingKey.publicKeyPem, "RS256");
    const jtis = new Set<string>();
    for (const token of tokens) {
      expect(decodeProtectedHeader(token).kid).toBe(KEY_ID);
      const { payload } = await jwtVerify(token, key, {
        audience: "datavalv",
        issuer: CLIENT_ID,
        requiredClaims: ["exp", "iat", "iss", "aud", "jti"],
      });
      expect(Number(payload.exp) - Number(payload.iat)).toBeLessThanOrEqual(MAX_ISSUED_LIFETIME);
      jtis.add(String(payload.jti));
    }
    expect(jtis.size, "a jti is recorded once; three calls need three of them").toBe(3);
  });

  test("the upload carries no Datavalv token", async () => {
    // The presigned URL is its own authorisation, and S3 refuses a second one.
    // The fake answers 400 InvalidArgument to an upload that carries an
    // `Authorization` header, so adding one to `uploadCiphertext` fails this
    // twice over.
    const fake = service();
    await makeClient(fake).pushBackup(EXTERNAL_ID, PLAINTEXT);

    const upload = fake.calls.find((call) => call.step === "PUT upload")!;
    expect(upload.token).toBeUndefined();
    expect(upload.headers.has("authorization")).toBe(false);
  });

  test("a replayed token is refused", async () => {
    // The single-use rule itself, stated directly rather than only implied.
    // This is what a hoisted header would run into. It also proves the fake is
    // capable of failing the test above, rather than passing it by not looking.
    const fake = service();
    await makeClient(fake).tenantPublicKey(EXTERNAL_ID);
    const replayed = fake.calls[0]!.headers.get("authorization")!;

    const response = await fake.fetch(`${API_BASE}/v1/tenants/${EXTERNAL_ID}/public-key`, {
      method: "GET",
      headers: { Authorization: replayed },
    });
    expect(response.status).toBe(403);
  });
});

// ------------------------------------------------------------------- digests

describe("the digest", () => {
  test("the body digest and the upload header are one digest", async () => {
    // Hex in the body, base64 in the header, one value underneath.
    //
    // Asserted as one relation on purpose: `sha256 === sha256(blob).hex` alone
    // passes while the header carries a different digest, and the header
    // assertion alone passes while the body does. The service checks both
    // against S3 at completion, so a client where they disagree fails at step 4
    // with a checksum mismatch and no indication which of the two was wrong.
    const fake = service();
    await makeClient(fake).pushBackup(EXTERNAL_ID, PLAINTEXT);

    const body = registered(fake);
    const upload = fake.calls.find((call) => call.step === "PUT upload")!;
    const headerB64 = upload.headers.get("x-amz-checksum-sha256")!;

    expect(Buffer.from(String(body["sha256"]), "hex")).toEqual(Buffer.from(headerB64, "base64"));
    expect(Buffer.from(String(body["sha256"]), "hex")).toEqual(
      createHash("sha256").update(upload.content).digest(),
    );
    expect(body["size"]).toBe(upload.content.length);
  });

  test("the digest is the ciphertext's and not the plaintext's", async () => {
    // The one substitution that looks right everywhere except at S3. Hashing
    // the plaintext is self-consistent in the request body and fails only when
    // S3 compares the signed checksum against what it actually received.
    const fake = service();
    await makeClient(fake).pushBackup(EXTERNAL_ID, PLAINTEXT);

    const body = registered(fake);
    expect(body["sha256"]).not.toBe(createHash("sha256").update(PLAINTEXT).digest("hex"));
    expect(body["sha256"]).toBe(createHash("sha256").update(fake.uploaded!).digest("hex"));
  });

  test("an upload without the checksum header is refused", async () => {
    // `x-amz-checksum-sha256` is required by the signature, not merely
    // accepted. Stated against the fake directly, the same way the replay test
    // is: it is what makes dropping the header from `uploadCiphertext` a
    // failing test rather than a silent change every other test here passes.
    const fake = service();
    const body = new Uint8Array(Buffer.from("anything"));
    const digest = createHash("sha256").update(body).digest().toString("base64");

    expect((await fake.fetch(UPLOAD_URL, { method: "PUT", body })).status).toBe(403);
    expect(
      (
        await fake.fetch(UPLOAD_URL, {
          method: "PUT",
          body,
          headers: { "x-amz-checksum-sha256": digest },
        })
      ).status,
    ).toBe(200);
    expect(
      (
        await fake.fetch(UPLOAD_URL, {
          method: "PUT",
          body: new Uint8Array(Buffer.from("something else")),
          headers: { "x-amz-checksum-sha256": digest },
        })
      ).status,
    ).toBe(400);
  });
});

// ----------------------------------------------------------- the crypto round

describe("the crypto round", () => {
  test("the uploaded ciphertext opens with the wrapped dek", async () => {
    // The end-to-end property the whole protocol exists for.
    //
    // A member's browser holds the tenant private key, unwraps `wrappedDekB64`
    // and decrypts what S3 stored. Standing in for that browser here is what
    // proves the DEK sent is the DEK used — the two are separate values in
    // `#push` and nothing else in this file would notice them diverging.
    const fake = service();
    await makeClient(fake).pushBackup(EXTERNAL_ID, PLAINTEXT, { name: "dump.sql.gz" });

    const body = registered(fake);
    expect(body["keyId"]).toBe(TENANT_KEY_ID);

    const dek = await unwrapDek(b64(String(body["wrappedDekB64"])), tenantKey.privateKeyPem);
    expect(await decrypt(fake.uploaded as Uint8Array<ArrayBuffer>, dek)).toEqual(PLAINTEXT);

    // `ivB64` is the payload's own IV, which is also inside the header the
    // ciphertext carries. A second, unrelated IV in that field would decrypt
    // here and still be wrong.
    expect(b64(String(body["ivB64"]))).toEqual(
      decodeHeader(fake.uploaded as Uint8Array<ArrayBuffer>),
    );
  });

  test("the filename is encrypted under the same dek with its own iv", async () => {
    // `nameCipherB64` opens with the backup's DEK — and reuses no nonce.
    //
    // Passing the payload's IV to the name's encryption would be catastrophic
    // rather than untidy: two messages under one AES-GCM key and one nonce. The
    // IV comparison is what makes that a failing test rather than a code
    // comment.
    const fake = service();
    await makeClient(fake).pushBackup(EXTERNAL_ID, PLAINTEXT, {
      name: "medlemsregister.sql.gz",
    });

    const body = registered(fake);
    const dek = await unwrapDek(b64(String(body["wrappedDekB64"])), tenantKey.privateKeyPem);
    const nameBlob = b64(String(body["nameCipherB64"]));

    expect(Buffer.from(await decrypt(nameBlob, dek)).toString("utf8")).toBe(
      "medlemsregister.sql.gz",
    );
    expect(decodeHeader(nameBlob)).not.toEqual(
      decodeHeader(fake.uploaded as Uint8Array<ArrayBuffer>),
    );
  });

  test("no name is sent when none is given", async () => {
    const fake = service();
    await makeClient(fake).pushBackup(EXTERNAL_ID, PLAINTEXT);
    expect(registered(fake)).not.toHaveProperty("nameCipherB64");
  });
});

// -------------------------------------------------------- what refusals mean

describe("what refusals mean", () => {
  test("409 on registering is retryable and says why", async () => {
    const fake = service();
    fake.failAt = FOUR_CALLS[1];
    fake.failure = { status: 409, body: DETAIL_409 };

    const error = await makeClient(fake)
      .pushBackup(EXTERNAL_ID, PLAINTEXT)
      .catch((exc: unknown) => exc);

    expect(error).toBeInstanceOf(VaultNotInitialized);
    const raised = error as VaultNotInitialized;
    expect(raised.retryable).toBe(true);
    expect(raised.status).toBe(409);
    expect(raised.code).toBe("tenant_not_initialized");
    expect(raised.message).toContain("step 2 of 4");
    // The sentence an operator reads instead of going to look for a fault.
    expect(raised.message).toContain("Nobody has started this vault yet");
  });

  test("409 on the public key is the same answer", async () => {
    // Both of the first two calls answer it, and both mean "not yet".
    const fake = service();
    fake.failAt = FOUR_CALLS[0];
    fake.failure = { status: 409, body: '{"code":"tenant_not_initialized"}' };

    const error = (await makeClient(fake)
      .pushBackup(EXTERNAL_ID, PLAINTEXT)
      .catch((exc: unknown) => exc)) as VaultNotInitialized;

    expect(error).toBeInstanceOf(VaultNotInitialized);
    expect(error.retryable).toBe(true);
    expect(error.message).toContain("step 1 of 4");
  });

  test.each([
    [413, '{"code":"too_large","detail":"exceeds the cap"}', "too_large"],
    [400, '{"code":"checksum_mismatch"}', "checksum_mismatch"],
    [404, '{"code":"tenant_not_found"}', "tenant_not_found"],
    [422, '{"code":"invalid_request"}', "invalid_request"],
    // A 409 that is *not* retryable, next to two that are. Sending the same
    // request again cannot change the answer: the key is already bound to a
    // different one.
    [409, '{"code":"idempotency_key_reused"}', "idempotency_key_reused"],
  ])("a %i is not retryable", async (status, body, code) => {
    // The other side of the 409: everything else needs a person. A client that
    // reported every 4xx as retryable would pass the 409 test above and turn a
    // permanent misconfiguration into a schedule that retries forever.
    const fake = service();
    fake.failAt = FOUR_CALLS[1];
    fake.failure = { status: status as number, body: body as string };

    const error = (await makeClient(fake)
      .pushBackup(EXTERNAL_ID, PLAINTEXT)
      .catch((exc: unknown) => exc)) as ApiError;

    expect(error).toBeInstanceOf(ApiError);
    expect(error.retryable).toBe(false);
    expect(error.code).toBe(code);
    expect(error).not.toBeInstanceOf(VaultNotInitialized);
  });

  test("a spent quota is retryable but is not an unstarted vault", async () => {
    const fake = service();
    fake.failAt = FOUR_CALLS[1];
    fake.failure = { status: 429, body: '{"code":"quota_exceeded","detail":"storage limit"}' };

    const error = (await makeClient(fake)
      .pushBackup(EXTERNAL_ID, PLAINTEXT)
      .catch((exc: unknown) => exc)) as QuotaExceeded;

    expect(error).toBeInstanceOf(QuotaExceeded);
    expect(error.retryable).toBe(true);
    expect(error).not.toBeInstanceOf(VaultNotInitialized);
  });

  test("a first attempt still running is retryable", async () => {
    // The 409 that means "not yet", as against the 409 that means "not ever".
    // A request that timed out on the wire and is retried inside the window is
    // exactly what the `Idempotency-Key` is sent for, and the honest answer
    // while the first attempt is still working is to come back in a moment.
    // Reporting it as fatal would abandon a backup that is at that moment
    // succeeding.
    const fake = service();
    fake.failAt = FOUR_CALLS[1];
    fake.failure = {
      status: 409,
      body: '{"code":"idempotency_in_progress","detail":"still running"}',
    };

    const error = (await makeClient(fake)
      .pushBackup(EXTERNAL_ID, PLAINTEXT)
      .catch((exc: unknown) => exc)) as RequestInFlight;

    expect(error).toBeInstanceOf(RequestInFlight);
    expect(error.retryable).toBe(true);
    expect(error.code).toBe("idempotency_in_progress");
    expect(error).not.toBeInstanceOf(VaultNotInitialized);
  });

  test("a vault that filled up mid-push is retryable", async () => {
    // The 409 that arrives after the bytes were sent. Distinct from
    // `quota_exceeded`, which refuses before an upload URL exists: this one
    // means another push finished in between, and the server discarded what
    // this one uploaded while touching nothing already stored. Retryable, but
    // the whole push repeats, because the blob is gone.
    const fake = service();
    fake.failAt = FOUR_CALLS[3];
    fake.failure = {
      status: 409,
      body: '{"code":"storage_full","detail":"storing this backup would leave 120 bytes"}',
    };

    const error = (await makeClient(fake)
      .pushBackup(EXTERNAL_ID, PLAINTEXT)
      .catch((exc: unknown) => exc)) as StorageFull;

    expect(error).toBeInstanceOf(StorageFull);
    expect(error.retryable).toBe(true);
    expect(error.code).toBe("storage_full");
    expect(error).not.toBeInstanceOf(QuotaExceeded);
  });

  test("an authorizer denial becomes an auth error", async () => {
    // API Gateway writes its own body, with no Datavalv code in it. The client
    // must still say something useful; a parser that required `code` would
    // throw here, inside the error path, where it is hardest to read.
    const fake = service();
    fake.failAt = FOUR_CALLS[0];
    fake.failure = { status: 403, body: '{"message":"Forbidden"}' };

    const error = (await makeClient(fake)
      .pushBackup(EXTERNAL_ID, PLAINTEXT)
      .catch((exc: unknown) => exc)) as AuthError;

    expect(error).toBeInstanceOf(AuthError);
    expect(error.code).toBeUndefined();
    expect(error.status).toBe(403);
    expect(error.retryable).toBe(false);
    expect(error.message).toContain("Forbidden");
    expect(error.message).toContain("/applications");
  });

  test("an upload refusal names storage and the step", async () => {
    const fake = service();
    fake.failAt = "PUT upload";
    fake.failure = { status: 403, body: "<Error><Code>AccessDenied</Code></Error>" };

    const error = (await makeClient(fake)
      .pushBackup(EXTERNAL_ID, PLAINTEXT)
      .catch((exc: unknown) => exc)) as UploadError;

    expect(error).toBeInstanceOf(UploadError);
    expect(error.message).toContain("step 3 of 4");
    expect(error.message).toContain("AccessDenied");
    expect(error.message).toContain("expired upload link");
  });

  test("a network failure is retryable and names the step", async () => {
    const client = new DatavalvClient({
      apiBase: API_BASE,
      clientId: CLIENT_ID,
      keyId: KEY_ID,
      privateKey: signingKey.privateKeyPem,
      fetch: async () => {
        throw new TypeError("fetch failed");
      },
    });

    const error = (await client
      .pushBackup(EXTERNAL_ID, PLAINTEXT)
      .catch((exc: unknown) => exc)) as NetworkError;

    expect(error).toBeInstanceOf(NetworkError);
    expect(error.retryable).toBe(true);
    expect(error.message).toContain("step 1 of 4");
  });
});

// ------------------------------------------------------------------- vaults

describe("vaults", () => {
  test("createVault sends only what it was given", async () => {
    // Unset fields are omitted, not nulled. `CreateTenantRequest` forbids
    // unknown fields and defaults the rest; `"locale": null` fails validation
    // rather than meaning "use the default", so a client that sent every field
    // always would 422 on the commonest call.
    const fake = service();
    const vault = await makeClient(fake).createVault(EXTERNAL_ID, "anna@example.se");

    expect(vault).toEqual({ tenantId: "t-1", status: "provisioned" });
    expect(fake.calls[0]!.json()).toEqual({
      externalId: EXTERNAL_ID,
      ownerEmail: "anna@example.se",
    });
  });

  test("createVault passes the optional fields through", async () => {
    const fake = service();
    await makeClient(fake).createVault(EXTERNAL_ID, "anna@example.se", {
      name: "Kund 4711",
      locale: "en",
      retentionCount: 7,
    });

    expect(fake.calls[0]!.json()).toEqual({
      externalId: EXTERNAL_ID,
      ownerEmail: "anna@example.se",
      name: "Kund 4711",
      locale: "en",
      retentionCount: 7,
    });
  });

  test("setRetention patches the vault", async () => {
    // The one source-app route neither client wrapped. Retention is settable
    // at creation and changeable for the life of the vault, and until this the
    // second half meant composing and signing the call by hand -- which is the
    // part of this protocol a client exists to do for you.
    const fake = service();
    await makeClient(fake).setRetention(EXTERNAL_ID, 12);

    const call = fake.calls[0]!;
    expect(call.method).toBe("PATCH");
    expect(call.url.pathname).toBe(`/v1/tenants/${EXTERNAL_ID}`);
    expect(call.json()).toEqual({ retentionCount: 12 });
  });

  test.each([0, -1, 366, 1.5, Number.NaN])(
    "setRetention refuses %p without spending a call",
    async (count) => {
      // Checked here rather than left to the 422: the server's range is
      // 1-365, and a signed call and a round trip is a slow way to be told
      // something the client already knew. 1.5 is in the list because a
      // fraction would be sent as `1.5` and read as invalid_request, which is
      // a confusing way to find out you did arithmetic.
      const fake = service();
      await expect(makeClient(fake).setRetention(EXTERNAL_ID, count)).rejects.toThrow(
        ConfigurationError,
      );
      expect(fake.calls).toEqual([]);
    },
  );

  test("deleteVault sends the confirmation the API asks for", async () => {
    // The most destructive route in the API, and the only one with a guard.
    // `DeleteTenantRequest.confirm` must repeat the identifier in the path or
    // the service answers `confirmation_mismatch`.
    const fake = service();
    const deleted = await makeClient(fake).deleteVault(EXTERNAL_ID, { confirm: EXTERNAL_ID });

    expect(deleted).toEqual({ tenantId: "t-1", status: "deleted" });
    const call = fake.calls[0]!;
    expect(call.method).toBe("DELETE");
    expect(call.url.pathname).toBe(`/v1/tenants/${EXTERNAL_ID}`);
    expect(call.json()).toEqual({ confirm: EXTERNAL_ID });
  });

  test("deleteVault will not confirm on the caller's behalf", async () => {
    // `confirm` is required and has no default, and a mismatch never goes
    // out. A client that defaulted it to `externalId` would be the one
    // implementation of this guard that cannot fail -- which is the same as
    // not having it.
    const fake = service();
    await expect(
      makeClient(fake).deleteVault(EXTERNAL_ID, { confirm: "kund-4712" }),
    ).rejects.toThrow(ConfigurationError);

    expect(fake.calls).toEqual([]);
  });

  test("listBackups returns the summaries", async () => {
    const fake = service();
    expect(await makeClient(fake).listBackups(EXTERNAL_ID)).toEqual([]);
  });
});

// ----------------------------------------------------------------- the rest

describe("the rest", () => {
  test("an idempotency key is sent when asked for", async () => {
    const fake = service();
    await makeClient(fake).pushBackup(EXTERNAL_ID, PLAINTEXT, {
      idempotencyKey: "nightly-2026-09-17",
    });

    const call = fake.calls.find((each) => each.step === FOUR_CALLS[1])!;
    expect(call.headers.get("idempotency-key")).toBe("nightly-2026-09-17");
  });

  test("no idempotency header when none was asked for", async () => {
    // A missing header is not an error at the API, and must stay missing here.
    // Sending a constant would be worse than sending none: two nights under one
    // key means the second night replays the first night's response.
    const fake = service();
    await makeClient(fake).pushBackup(EXTERNAL_ID, PLAINTEXT);

    const call = fake.calls.find((each) => each.step === FOUR_CALLS[1])!;
    expect(call.headers.has("idempotency-key")).toBe(false);
  });

  test.each([API_BASE, `${API_BASE}/`, `${API_BASE}/v1`])(
    "the api base is accepted as %s",
    async (given) => {
      // Both spellings are in this project's own runbooks and samples.
      const fake = service();
      await makeClient(fake, given).tenantPublicKey(EXTERNAL_ID);
      expect(fake.calls[0]!.url.pathname).toBe(`/v1/tenants/${EXTERNAL_ID}/public-key`);
    },
  );

  test("a private key path is refused rather than read", () => {
    // `DATAVALV_PRIVATE_KEY` is a path; this argument is the key. Accepting
    // both would make the two interchangeable, which is how a key ends up in an
    // environment variable — and in `ps`, and in the shell history.
    expect(
      () =>
        new DatavalvClient({
          apiBase: API_BASE,
          clientId: CLIENT_ID,
          keyId: KEY_ID,
          privateKey: "/etc/datavalv/signing.pem",
        }),
    ).toThrow(/looks like a\s+filename/);
  });

  test("missing settings are refused before any request", async () => {
    const fake = service();
    for (const missing of ["apiBase", "clientId", "keyId"] as const) {
      const options = {
        apiBase: API_BASE,
        clientId: CLIENT_ID,
        keyId: KEY_ID,
        privateKey: signingKey.privateKeyPem,
        fetch: fake.fetch,
      };
      options[missing] = "";
      expect(() => new DatavalvClient(options)).toThrow(ConfigurationError);
    }
    expect(fake.calls).toEqual([]);
  });

  test("an over-long label fails before the file is encrypted", async () => {
    const fake = service();
    await expect(
      makeClient(fake).pushBackup(EXTERNAL_ID, PLAINTEXT, { label: "x".repeat(201) }),
    ).rejects.toThrow(/caps it at 200/);
    expect(fake.calls).toEqual([]);
  });

  test("a push asked to keep says so to the service", async () => {
    const fake = service();
    const pushed = await makeClient(fake).pushBackup(EXTERNAL_ID, PLAINTEXT, { keep: true });
    expect(fake.calls[1]!.json()["keep"]).toBe(true);
    expect(pushed.kept).toBe(true);
  });

  test("an ordinary push sends no keep at all", async () => {
    // Absent rather than false, so the body an ordinary push sends is the one
    // it always sent.
    const fake = service();
    const pushed = await makeClient(fake).pushBackup(EXTERNAL_ID, PLAINTEXT);
    expect(fake.calls[1]!.json()).not.toHaveProperty("keep");
    expect(pushed.kept).toBe(false);
  });
});

function b64(text: string): Uint8Array<ArrayBuffer> {
  return new Uint8Array(Buffer.from(text, "base64"));
}

// --------------------------------------------- key material never leaves

describe("a private key in a field", () => {
  // The same shapes `applications.ts` refuses in the browser and
  // `client.py` refuses on the Python side: a block, in any PEM label and
  // any case, plus PuTTY's own format, which has no BEGIN line at all.
  const spellings = [
    "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----",
    "-----BEGIN OPENSSH PRIVATE KEY-----\nb3Blbn\n-----END OPENSSH PRIVATE KEY-----",
    "-----begin ec private key-----\nMHcCAQ\n-----end ec private key-----",
    "PuTTY-User-Key-File-3: ssh-rsa\nPrivate-Lines: 14\nAAAA",
  ];

  test.each(spellings)("is refused before anything is sent: %s", async (leaked) => {
    // Nothing here asks for a private key -- the signing key is read from a
    // file and used to sign, and every field a caller fills in is a name, a
    // label or a digest. One in a field is a paste that went into the wrong
    // argument, and after the request it has been in somebody else's logs
    // whatever anybody does about it next.
    const fake = service();

    await expect(
      makeClient(fake).createVault(EXTERNAL_ID, "anna@example.se", { name: leaked }),
    ).rejects.toThrow(ConfigurationError);
    expect(fake.calls).toEqual([]);
  });

  test("the words alone are a label, not a key", async () => {
    // A guard that refused the words would refuse "nightly private key
    // backup", which somebody will legitimately write.
    const fake = service();

    await makeClient(fake).createVault(EXTERNAL_ID, "anna@example.se", {
      name: "private key backups",
    });

    expect(fake.calls.map((call) => call.step)).toEqual(["POST /v1/tenants"]);
  });
});
