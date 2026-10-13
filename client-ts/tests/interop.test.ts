/**
 * A backup this client produces opens with the Python client, and the reverse.
 *
 * This is the test neither package can write alone, and the reason there can be
 * two implementations of one format at all. Everything else in this suite
 * checks that `@datavalv/client` agrees with itself; agreeing with itself is
 * exactly what a drifted implementation does.
 *
 * Nothing here re-implements the format on either side. A real HTTP server
 * stands in for Datavalv and S3, and the two clients are run against it as they
 * would run in production:
 *
 * * **ts → py** — `DatavalvClient.pushBackup` encrypts and uploads; the bytes
 *   the server received go to `python -m datavalv_client.conformance decrypt`,
 *   which is the Python package's own decryptor and the same entry point the
 *   repository's conformance matrix drives.
 * * **py → ts** — `datavalv_client.DatavalvClient.push_backup` runs in a
 *   subprocess against the same server, and `@datavalv/crypto` opens what it
 *   uploaded.
 *
 * The two directions deliberately use tenant keypairs made by *different*
 * implementations — `cryptography` for one, WebCrypto for the other — because
 * RSA-OAEP wrapping against a key the other side generated is its own crossing,
 * and a suite where both keys came from one library would not test it.
 *
 * The filenames are the conformance matrix's: Swedish letters and an en dash,
 * which is where a UTF-8 defect lives. A name is encrypted under the payload's
 * DEK and read back in a member's browser, so it crosses the boundary as *text*
 * rather than as opaque bytes.
 *
 * If `uv` or the Python client is missing this file fails rather than skips. A
 * cross-implementation test that quietly stops running is the drift it exists
 * to prevent.
 */

import { execFile } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createHash } from "node:crypto";
import { promisify } from "node:util";

import { afterAll, beforeAll, describe, expect, test } from "vitest";

import { decodeHeader, decrypt, generateKeypair, unwrapDek } from "@datavalv/crypto";

import { DatavalvClient } from "../src/client.js";
import { StubService, jtisOf } from "./support/stubService.js";
import { CLIENT_ID, EXTERNAL_ID, KEY_ID, TENANT_KEY_ID } from "./support/fakeDatavalv.js";
import { signingKey } from "./support/fixtures.js";

const execFileAsync = promisify(execFile);

const REPO_ROOT = path.resolve(import.meta.dirname, "..", "..");
const PUSH_WITH_PYTHON = path.join(import.meta.dirname, "support/push_with_python.py");

const PLAINTEXT = Buffer.from(
  "-- pg_dump 17.2\nCREATE TABLE medlem (id int, namn text);\n".repeat(200) +
    // Bytes that are not text at all, beside text that is: a backup is a gzip
    // stream, and a client that decoded its payload anywhere would survive the
    // ASCII above and corrupt this.
    String.fromCharCode(...Array.from({ length: 256 }, (_, i) => i)),
  "binary",
);

/** The conformance matrix's filename cases, for the reason it lists. */
const FILENAME = "Årsmöte – protokoll 2026 – Bromma Segelsällskap.pdf";

let stub: StubService;
let apiBase: string;
let keyPath: string;
let tmp: string;

beforeAll(async () => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), "datavalv-interop-"));
  // Written the way an operator's key is: a path, at mode 600. The Python
  // client reads it through `DATAVALV_PRIVATE_KEY`, so the key this TypeScript
  // package generated is also the key the Python package signs with.
  keyPath = path.join(tmp, "datavalv-signing.pem");
  fs.writeFileSync(keyPath, signingKey.privateKeyPem, { mode: 0o600 });
  fs.chmodSync(keyPath, 0o600);

  stub = new StubService({
    tenantPublicPem: "",
    tenantKeyId: TENANT_KEY_ID,
    signingPublicPem: signingKey.publicKeyPem,
    clientId: CLIENT_ID,
    keyId: KEY_ID,
    externalId: EXTERNAL_ID,
    backupId: "bk_01J8Z6QK9T",
  });
  apiBase = await stub.listen();
});

afterAll(async () => {
  await stub.close();
  fs.rmSync(tmp, { recursive: true, force: true });
});

// -------------------------------------------------------------- the Python side

/** `uv run` from the repository root, where `datavalv_client` is a workspace member. */
async function python(
  args: string[],
  options: { input?: Buffer | string; env?: NodeJS.ProcessEnv } = {},
): Promise<string> {
  const child = execFile(
    "uv",
    ["run", "python", ...args],
    {
      cwd: REPO_ROOT,
      env: { ...process.env, ...options.env },
      maxBuffer: 64 * 1024 * 1024,
      // Buffers, not strings: the plaintext that goes in is binary, and a
      // stdout decoded per chunk can split a multi-byte character across two.
      encoding: "buffer",
    },
    () => {},
  );
  const stdout: Buffer[] = [];
  const stderr: Buffer[] = [];
  child.stdout?.on("data", (chunk: Buffer) => stdout.push(chunk));
  child.stderr?.on("data", (chunk: Buffer) => stderr.push(chunk));
  if (options.input !== undefined) child.stdin?.end(options.input);
  else child.stdin?.end();

  const code = await new Promise<number>((resolve, reject) => {
    child.on("error", reject);
    child.on("close", resolve);
  });
  if (code !== 0) {
    throw new Error(
      `uv run python ${args.join(" ")} exited ${code}\n${Buffer.concat(stderr).toString("utf8")}`,
    );
  }
  return Buffer.concat(stdout).toString("utf8");
}

/** The Python package's own decryptor, driven through its conformance contract. */
async function pythonDecrypt(job: {
  ciphertextB64: string;
  wrappedDekB64: string;
  privateKeyPem: string;
}): Promise<{ plaintextB64?: string; error?: string }> {
  const out = await python(["-m", "datavalv_client.conformance", "decrypt"], {
    input: JSON.stringify(job),
  });
  return JSON.parse(out) as { plaintextB64?: string; error?: string };
}

async function pythonTenantKeypair(): Promise<{ publicKeyPem: string; privateKeyPem: string }> {
  const program =
    "import json,sys;from datavalv_client import crypto;"
    + "k=crypto.generate_keypair();"
    + "json.dump({'publicKeyPem':crypto.public_key_to_pem(k.public_key()),"
    + "'privateKeyPem':crypto.private_key_to_pem(k)},sys.stdout)";
  return JSON.parse(await python(["-c", program])) as {
    publicKeyPem: string;
    privateKeyPem: string;
  };
}

// ------------------------------------------------------------------- the tests

describe("one format, two implementations", () => {
  test("uv and the Python client are here — this file must not skip", async () => {
    // The guard under the guard. Both directions below would pass vacuously in
    // a suite that decided Python was unavailable and moved on, and the day
    // that happens is the day the two implementations are free to drift.
    const version = (await python(["-c", "import datavalv_client;print(datavalv_client.__version__)"])).trim();
    expect(version).toMatch(/^\d+\.\d+\.\d+$/);
  });

  test("a backup this client produces decrypts with the Python client", async () => {
    // The tenant keypair comes from `cryptography`, so the RSA-OAEP wrap below
    // is against a key this side did not make.
    const tenant = await pythonTenantKeypair();
    stub.state.tenantPublicPem = tenant.publicKeyPem;

    const client = new DatavalvClient({
      apiBase,
      clientId: CLIENT_ID,
      keyId: KEY_ID,
      privateKey: signingKey.privateKeyPem,
    });
    const pushed = await client.pushBackup(EXTERNAL_ID, new Uint8Array(PLAINTEXT), {
      name: FILENAME,
      label: "nightly",
    });

    const registered = stub.registered!;
    const uploaded = stub.uploaded!;
    expect(pushed.sha256).toBe(createHash("sha256").update(uploaded).digest("hex"));

    // The payload, opened by Python with the DEK Python unwrapped for itself.
    const payload = await pythonDecrypt({
      ciphertextB64: uploaded.toString("base64"),
      wrappedDekB64: String(registered["wrappedDekB64"]),
      privateKeyPem: tenant.privateKeyPem,
    });
    expect(payload.error, "Python refused a backup this client produced").toBeUndefined();
    expect(Buffer.from(payload.plaintextB64!, "base64")).toEqual(PLAINTEXT);

    // The filename, opened by Python under the same DEK and compared as TEXT.
    // Comparing base64 would pass for two encodings of the same name that a
    // member's browser renders differently.
    const name = await pythonDecrypt({
      ciphertextB64: String(registered["nameCipherB64"]),
      wrappedDekB64: String(registered["wrappedDekB64"]),
      privateKeyPem: tenant.privateKeyPem,
    });
    expect(name.error).toBeUndefined();
    expect(Buffer.from(name.plaintextB64!, "base64").toString("utf8")).toBe(FILENAME);
  });

  test("a backup the Python client produces decrypts with this one", async () => {
    // The tenant keypair comes from WebCrypto this time, so the Python client
    // wraps against a key `@datavalv/crypto` made.
    const tenant = await generateKeypair();
    stub.state.tenantPublicPem = tenant.publicKeyPem;
    stub.uploaded = undefined;
    stub.registered = undefined;

    const summary = JSON.parse(
      await python(
        [
          PUSH_WITH_PYTHON,
          "--api",
          apiBase,
          "--external-id",
          EXTERNAL_ID,
          "--name",
          FILENAME,
          "--label",
          "nightly",
        ],
        {
          input: PLAINTEXT,
          env: {
            DATAVALV_CLIENT_ID: CLIENT_ID,
            DATAVALV_KEY_ID: KEY_ID,
            DATAVALV_PRIVATE_KEY: keyPath,
          },
        },
      ),
    ) as { sha256: string; size: number };

    const registered = stub.registered!;
    const uploaded = stub.uploaded!;
    expect(summary.sha256).toBe(createHash("sha256").update(uploaded).digest("hex"));

    const dek = await unwrapDek(b64(String(registered["wrappedDekB64"])), tenant.privateKeyPem);
    expect(Buffer.from(await decrypt(bytes(uploaded), dek))).toEqual(PLAINTEXT);
    expect(
      Buffer.from(await decrypt(b64(String(registered["nameCipherB64"])), dek)).toString("utf8"),
    ).toBe(FILENAME);

    // `ivB64` is the payload's own IV, and the header the Python client wrote
    // carries it too. This is the field a browser reads before it has the
    // blob's bytes, so the two must be the same value on both sides.
    expect(b64(String(registered["ivB64"]))).toEqual(decodeHeader(bytes(uploaded)));
  });

  test("the Python client's push obeys the same three rules over the wire", async () => {
    // Asserted against the server the previous test drove, so these are facts
    // about the run that just crossed the boundary rather than a second push.
    //
    // Nothing here is about the format. It is about the protocol both clients
    // implement, checked once against a real socket: the header the runtime put
    // on the upload, the credentials the presigned PUT must not carry, and one
    // token per call.
    const upload = stub.uploadCall!;
    expect(upload.headers["authorization"]).toBeUndefined();
    expect(upload.headers["x-amz-checksum-sha256"]).toBe(
      createHash("sha256").update(stub.uploaded!).digest("base64"),
    );
    // `presigned_put` signs ContentLength as well as the checksum; a body sent
    // chunked would have no length at all and S3 would answer 403.
    expect(Number(upload.headers["content-length"])).toBe(Number(stub.registered!["size"]));

    const jtis = jtisOf(stub.calls);
    expect(jtis.length, "three Datavalv calls per push, in both directions").toBe(6);
    expect(new Set(jtis).size, "a jti is spent on arrival; no two calls may share one").toBe(6);
  });
});

function b64(text: string): Uint8Array<ArrayBuffer> {
  return new Uint8Array(Buffer.from(text, "base64"));
}

function bytes(buffer: Buffer): Uint8Array<ArrayBuffer> {
  return new Uint8Array(buffer);
}
