/**
 * `datavalv`, from an operator's side: what it writes, what it prints, and what
 * it exits with.
 *
 * Two things are worth more than the rest here. `keygen` must never let the
 * private half reach stdout, a log or a terminal, and a schedule must be able
 * to tell "the vault has not been started yet" from "something is broken"
 * without reading prose — which is what the exit codes are for.
 */

import { execFile } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { createPrivateKey, createPublicKey } from "node:crypto";

import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";

import { decrypt, generateKeypair, publicKeyFingerprint, unwrapDek } from "@datavalv/crypto";

import * as cli from "../src/cli.js";
import { VERSION } from "../src/index.js";
import {
  API_BASE,
  BACKUP_ID,
  CLIENT_ID,
  EXTERNAL_ID,
  FakeDatavalv,
  KEY_ID,
} from "./support/fakeDatavalv.js";
import { signingKey, tenantKey } from "./support/fixtures.js";

const run = promisify(execFile);
const PLAINTEXT = Buffer.from("-- a database dump\n".repeat(32));
const SETTINGS = [
  "DATAVALV_API",
  "DATAVALV_CLIENT_ID",
  "DATAVALV_KEY_ID",
  "DATAVALV_PRIVATE_KEY",
] as const;

let tmp: string;
let ambient: Partial<Record<string, string | undefined>>;

beforeEach(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), "datavalv-cli-"));
  // The developer's own shell must not decide what these tests test.
  ambient = Object.fromEntries(SETTINGS.map((name) => [name, process.env[name]]));
  for (const name of SETTINGS) delete process.env[name];
});

afterEach(() => {
  for (const name of SETTINGS) {
    const value = ambient[name];
    if (value === undefined) delete process.env[name];
    else process.env[name] = value;
  }
  fs.rmSync(tmp, { recursive: true, force: true });
});

interface Run {
  code: number;
  out: string;
  err: string;
}

/** `main`, with both streams captured rather than printed into the report. */
async function datavalv(argv: string[], options: cli.MainOptions = {}): Promise<Run> {
  const out: string[] = [];
  const err: string[] = [];
  const outSpy = vi.spyOn(process.stdout, "write").mockImplementation((chunk) => {
    out.push(String(chunk));
    return true;
  });
  const errSpy = vi.spyOn(process.stderr, "write").mockImplementation((chunk) => {
    err.push(String(chunk));
    return true;
  });
  try {
    const code = await cli.main(argv, options);
    return { code, out: out.join(""), err: err.join("") };
  } finally {
    outSpy.mockRestore();
    errSpy.mockRestore();
  }
}

function service(): FakeDatavalv {
  return new FakeDatavalv({
    signingPublicPem: signingKey.publicKeyPem,
    tenantPublicPem: tenantKey.publicKeyPem,
  });
}

function keyFile(): string {
  const file = path.join(tmp, "datavalv-signing.pem");
  fs.writeFileSync(file, signingKey.privateKeyPem, { mode: 0o600 });
  fs.chmodSync(file, 0o600);
  return file;
}

function connection(file: string): string[] {
  return [
    "--api",
    API_BASE,
    "--client-id",
    CLIENT_ID,
    "--key-id",
    KEY_ID,
    "--private-key",
    file,
  ];
}

function dump(): string {
  const file = path.join(tmp, "dump.sql.gz");
  fs.writeFileSync(file, PLAINTEXT);
  return file;
}

function modeOf(file: string): number {
  return fs.statSync(file).mode & 0o777;
}

// ------------------------------------------------------------------- keygen

describe("keygen", () => {
  test("writes a private key only its owner can read", async () => {
    const out = path.join(tmp, "signing.pem");
    expect((await datavalv(["keygen", "--out", out])).code).toBe(cli.EXIT_OK);

    expect(modeOf(out), `mode is ${modeOf(out).toString(8)}`).toBe(0o600);
    expect(fs.readFileSync(out, "utf8")).toContain("PRIVATE KEY");
  });

  test("creates the key at 0600 rather than fixing it afterwards", async () => {
    // The file must never exist readable, not merely end up unreadable.
    //
    // The test above passes for a `keygen` that creates the file world-readable
    // and chmods it a moment later — and that moment is the whole
    // vulnerability: anything watching the directory wins the race and has the
    // key. So `tests/support/keygenUnderPermissiveUmask.ts` neuters the chmod
    // and opens the umask right up, which leaves the mode passed to `open` as
    // the only thing that can produce 0600. Probed by changing that mode to
    // 0o666: the file comes out 0666 and this fails.
    const out = path.join(tmp, "signing.pem");
    const harness = path.join(import.meta.dirname, "support/keygenUnderPermissiveUmask.ts");

    await run(process.execPath, ["--import", "tsx", harness, out], {
      cwd: path.join(import.meta.dirname, ".."),
    });

    expect(modeOf(out)).toBe(0o600);
  });

  test("--force creates the replacement at 0600 rather than reusing the old mode", async () => {
    // The `--force` path has its own way of leaving a key readable: truncating
    // the existing file instead of unlinking it keeps whatever mode that file
    // already had — which may be exactly the mode that made replacing the key
    // necessary. The test below cannot see it, because the chmod tidy-up
    // corrects the finished file; this one neuters that chmod, so only the
    // unlink-and-create-fresh arrangement produces 0600.
    const out = path.join(tmp, "signing.pem");
    fs.writeFileSync(out, "the key that is being retired\n");
    fs.chmodSync(out, 0o666);
    const harness = path.join(import.meta.dirname, "support/keygenUnderPermissiveUmask.ts");

    await run(process.execPath, ["--import", "tsx", harness, out, "--force"], {
      cwd: path.join(import.meta.dirname, ".."),
    });

    expect(fs.readFileSync(out, "utf8")).toContain("PRIVATE KEY");
    expect(modeOf(out)).toBe(0o600);
  });

  test("never prints the private half", async () => {
    // The one output this command must not produce. Probed by making `keygen`
    // print the private PEM instead of the public one: this fails, and so does
    // the test below, which is the pair that makes "prints something" and
    // "prints the right thing" separate questions.
    const out = path.join(tmp, "signing.pem");
    const { out: stdout, err } = await datavalv(["keygen", "--out", out]);

    for (const stream of [stdout, err]) {
      expect(stream).not.toContain("PRIVATE KEY");
      expect(stream).not.toContain("-----BEGIN RSA");
    }
    // Not a single line of the key file, either: a key printed in pieces is
    // still a key printed.
    const body = fs
      .readFileSync(out, "utf8")
      .split("\n")
      .filter((line) => line && !line.includes("-----"));
    expect(body.length, "the key file should have content").toBeGreaterThan(0);
    for (const line of body) {
      expect(stdout).not.toContain(line);
      expect(err).not.toContain(line);
    }
  });

  test("prints the public half of the key it wrote", async () => {
    const out = path.join(tmp, "signing.pem");
    const { out: stdout } = await datavalv(["keygen", "--out", out]);

    const onDisk = createPrivateKey(fs.readFileSync(out, "utf8"));
    const expected = createPublicKey(onDisk)
      .export({ type: "spki", format: "pem" })
      .toString();
    expect(stdout.trim()).toBe(expected.trim());
    expect(onDisk.asymmetricKeyDetails?.modulusLength).toBe(3072);
  });

  test("refuses to replace an existing key", async () => {
    // A key file that is already registered is not something to overwrite by
    // accident: the replacement signs nothing the service will accept.
    const out = path.join(tmp, "signing.pem");
    fs.writeFileSync(out, "existing\n");

    const { code, err } = await datavalv(["keygen", "--out", out]);
    expect(code).toBe(cli.EXIT_FAILED);
    expect(fs.readFileSync(out, "utf8")).toBe("existing\n");
    expect(err).toContain("--force");
  });

  test("--force replaces it and still writes 0600", async () => {
    const out = path.join(tmp, "signing.pem");
    fs.writeFileSync(out, "existing\n");
    fs.chmodSync(out, 0o644);

    expect((await datavalv(["keygen", "--out", out, "--force"])).code).toBe(cli.EXIT_OK);
    expect(fs.readFileSync(out, "utf8")).toContain("PRIVATE KEY");
    expect(modeOf(out)).toBe(0o600);
  });
});

// ------------------------------------------------------------------ settings

describe("settings", () => {
  test.each([
    ["--api", "DATAVALV_API"],
    ["--client-id", "DATAVALV_CLIENT_ID"],
    ["--key-id", "DATAVALV_KEY_ID"],
    ["--private-key", "DATAVALV_PRIVATE_KEY"],
  ])("a missing %s names the flag and the variable", async (flag, envName) => {
    const argv = connection(keyFile());
    argv.splice(argv.indexOf(flag), 2);
    const fake = service();

    const { code, err } = await datavalv(
      ["push", dump(), "--external-id", EXTERNAL_ID, ...argv],
      { fetch: fake.fetch },
    );

    expect(code).toBe(cli.EXIT_CONFIG);
    expect(err).toContain(flag);
    expect(err).toContain(envName);
    expect(fake.calls, "nothing should be sent before the settings are complete").toEqual([]);
  });

  test("settings fall back to the environment", async () => {
    const file = keyFile();
    process.env["DATAVALV_API"] = API_BASE;
    process.env["DATAVALV_CLIENT_ID"] = CLIENT_ID;
    process.env["DATAVALV_KEY_ID"] = KEY_ID;
    process.env["DATAVALV_PRIVATE_KEY"] = file;
    const fake = service();

    const { code } = await datavalv(["push", dump(), "--external-id", EXTERNAL_ID], {
      fetch: fake.fetch,
    });

    expect(code).toBe(cli.EXIT_OK);
    expect(fake.calls).toHaveLength(4);
  });

  test("the key itself in the environment is refused and not echoed", async () => {
    // `DATAVALV_PRIVATE_KEY` is a path, and the failure must not print the key.
    // Letting `readFileSync(pem)` fail naturally would report the filename it
    // could not open — which is the operator's private key, on stderr and into
    // whatever collects their cron output.
    process.env["DATAVALV_API"] = API_BASE;
    process.env["DATAVALV_CLIENT_ID"] = CLIENT_ID;
    process.env["DATAVALV_KEY_ID"] = KEY_ID;
    process.env["DATAVALV_PRIVATE_KEY"] = signingKey.privateKeyPem;
    const fake = service();

    const { code, out, err } = await datavalv(
      ["push", dump(), "--external-id", EXTERNAL_ID],
      { fetch: fake.fetch },
    );

    expect(code).toBe(cli.EXIT_CONFIG);
    for (const line of signingKey.privateKeyPem.split("\n")) {
      if (line.trim() && !line.includes("-----")) {
        expect(err).not.toContain(line);
        expect(out).not.toContain(line);
      }
    }
    expect(err).toContain("path");
  });

  test("a world-readable key warns but still works", async () => {
    // A permission bit must not cost a night's backup — but must be said.
    const file = keyFile();
    fs.chmodSync(file, 0o644);
    const fake = service();

    const { code, err } = await datavalv(
      ["push", dump(), "--external-id", EXTERNAL_ID, ...connection(file)],
      { fetch: fake.fetch },
    );

    expect(code).toBe(cli.EXIT_OK);
    expect(err).toContain("readable by others");
  });
});

// ---------------------------------------------------------------------- push

describe("push", () => {
  test("prints the backup id and nothing else on stdout", async () => {
    // `BACKUP=$(datavalv push …)` has to hold an id, not a paragraph.
    const fake = service();
    const { code, out } = await datavalv(
      ["push", dump(), "--external-id", EXTERNAL_ID, ...connection(keyFile())],
      { fetch: fake.fetch },
    );

    expect(code).toBe(cli.EXIT_OK);
    expect(out.trim()).toBe(BACKUP_ID);
    expect(fake.calls).toHaveLength(4);
  });

  test("encrypts the basename and not the path", async () => {
    // The name that travels is `dump.sql.gz`, encrypted — never the directory.
    // Opened here with the tenant key, the way a member's browser will:
    // asserting only that the field is present passes for a client that sends
    // the whole absolute path, which tells a reader where this server keeps its
    // dumps.
    const fake = service();
    await datavalv(
      ["push", dump(), "--external-id", EXTERNAL_ID, ...connection(keyFile())],
      { fetch: fake.fetch },
    );

    const body = fake.calls[1]!.json();
    const dek = await unwrapDek(b64(String(body["wrappedDekB64"])), tenantKey.privateKeyPem);
    const name = Buffer.from(await decrypt(b64(String(body["nameCipherB64"])), dek)).toString(
      "utf8",
    );
    expect(name).toBe("dump.sql.gz");
    expect(name).not.toContain(tmp);
  });

  test("sends the name it was told to send", async () => {
    // `--name-as`, for a dump written to a temporary file with a useless name.
    const fake = service();
    await datavalv(
      [
        "push",
        dump(),
        "--external-id",
        EXTERNAL_ID,
        "--name-as",
        "medlemsregister-2026-09-17.sql.gz",
        ...connection(keyFile()),
      ],
      { fetch: fake.fetch },
    );

    const body = fake.calls[1]!.json();
    const dek = await unwrapDek(b64(String(body["wrappedDekB64"])), tenantKey.privateKeyPem);
    expect(
      Buffer.from(await decrypt(b64(String(body["nameCipherB64"])), dek)).toString("utf8"),
    ).toBe("medlemsregister-2026-09-17.sql.gz");
  });

  test("sends no name when told not to", async () => {
    const fake = service();
    await datavalv(
      ["push", dump(), "--external-id", EXTERNAL_ID, "--no-name", ...connection(keyFile())],
      { fetch: fake.fetch },
    );
    expect(fake.calls[1]!.json()).not.toHaveProperty("nameCipherB64");
  });

  test("reads stdin and sends no name", async () => {
    // `pg_dump … | datavalv push -` — and no filename to invent.
    const fake = service();
    const { code } = await datavalv(
      ["push", "-", "--external-id", EXTERNAL_ID, ...connection(keyFile())],
      { fetch: fake.fetch, stdin: async () => new Uint8Array(PLAINTEXT) },
    );

    expect(code).toBe(cli.EXIT_OK);
    expect(fake.calls[1]!.json()).not.toHaveProperty("nameCipherB64");
    expect(fake.uploaded).toBeDefined();
    const body = fake.calls[1]!.json();
    const dek = await unwrapDek(b64(String(body["wrappedDekB64"])), tenantKey.privateKeyPem);
    expect(Buffer.from(await decrypt(fake.uploaded as Uint8Array<ArrayBuffer>, dek))).toEqual(
      PLAINTEXT,
    );
  });

  test("passes the label and the idempotency key", async () => {
    const fake = service();
    await datavalv(
      [
        "push",
        dump(),
        "--external-id",
        EXTERNAL_ID,
        "--label",
        "nattlig",
        "--idempotency-key",
        "2026-09-17",
        ...connection(keyFile()),
      ],
      { fetch: fake.fetch },
    );
    expect(fake.calls[1]!.json()["label"]).toBe("nattlig");
    expect(fake.calls[1]!.headers.get("idempotency-key")).toBe("2026-09-17");
  });

  test("--keep asks for the copy to outlive retention", async () => {
    const fake = service();
    const { code, out, err } = await datavalv(
      ["push", dump(), "--external-id", EXTERNAL_ID, "--keep", ...connection(keyFile())],
      { fetch: fake.fetch },
    );
    expect(code).toBe(cli.EXIT_OK);
    expect(fake.calls[1]!.json()["keep"]).toBe(true);
    expect(out.trim()).toBe(BACKUP_ID);
    expect(err).toContain("kept until a member deletes it");
  });

  test("a missing file is a configuration exit, not a stack trace", async () => {
    const fake = service();
    const { code, err } = await datavalv(
      [
        "push",
        path.join(tmp, "nothing-here.sql.gz"),
        "--external-id",
        EXTERNAL_ID,
        ...connection(keyFile()),
      ],
      { fetch: fake.fetch },
    );

    expect(code).toBe(cli.EXIT_CONFIG);
    expect(err).toContain("nothing-here.sql.gz");
    expect(err).not.toContain("    at ");
  });
});

// --------------------------------------------------------------- exit codes

describe("exit codes", () => {
  test("an unstarted vault exits 5 and says to wait", async () => {
    // The code a nightly schedule branches on. 5 rather than 1 is the whole
    // point: `tenant_not_initialized` means nobody has signed in yet, and a job
    // that treats it as a fault sends somebody looking for a broken server.
    const fake = service();
    fake.failAt = `GET /v1/tenants/${EXTERNAL_ID}/public-key`;
    fake.failure = { status: 409, body: '{"code":"tenant_not_initialized"}' };

    const { code, err } = await datavalv(
      ["push", dump(), "--external-id", EXTERNAL_ID, ...connection(keyFile())],
      { fetch: fake.fetch },
    );

    expect(code).toBe(cli.EXIT_RETRY);
    expect(err).toContain("Nobody has started this vault yet");
    expect(err).toContain("step 1 of 4");
  });

  test("a refused key exits 4", async () => {
    const fake = service();
    fake.failAt = `GET /v1/tenants/${EXTERNAL_ID}/public-key`;
    fake.failure = { status: 403, body: '{"message":"Forbidden"}' };

    const { code, err } = await datavalv(
      ["push", dump(), "--external-id", EXTERNAL_ID, ...connection(keyFile())],
      { fetch: fake.fetch },
    );

    expect(code).toBe(cli.EXIT_AUTH);
    expect(err).toContain("/applications");
  });

  test("another refusal exits 6", async () => {
    const fake = service();
    fake.failAt = `POST /v1/tenants/${EXTERNAL_ID}/backups`;
    fake.failure = {
      status: 413,
      body: '{"code":"too_large","detail":"600000000 bytes exceeds"}',
    };

    const { code, err } = await datavalv(
      ["push", dump(), "--external-id", EXTERNAL_ID, ...connection(keyFile())],
      { fetch: fake.fetch },
    );

    expect(code).toBe(cli.EXIT_REFUSED);
    expect(err).toContain("too_large");
  });

  test("the eight exit codes are distinct", () => {
    // They are a branchable surface; two of them being equal is a silent bug.
    const codes = [
      cli.EXIT_OK,
      cli.EXIT_FAILED,
      cli.EXIT_USAGE,
      cli.EXIT_CONFIG,
      cli.EXIT_AUTH,
      cli.EXIT_RETRY,
      cli.EXIT_REFUSED,
      cli.EXIT_KEY_CHANGED,
    ];
    expect(new Set(codes).size).toBe(codes.length);
  });

  test("the codes are the Python client's, value for value", () => {
    // A shop running both clients writes one rule in one scheduler. These
    // numbers are `client/src/datavalv_client/cli.py`'s, and a change to either
    // side without the other is what makes that rule wrong somewhere.
    expect({
      ok: cli.EXIT_OK,
      failed: cli.EXIT_FAILED,
      usage: cli.EXIT_USAGE,
      config: cli.EXIT_CONFIG,
      auth: cli.EXIT_AUTH,
      retry: cli.EXIT_RETRY,
      refused: cli.EXIT_REFUSED,
      keyChanged: cli.EXIT_KEY_CHANGED,
    }).toEqual({
      ok: 0,
      failed: 1,
      usage: 2,
      config: 3,
      auth: 4,
      retry: 5,
      refused: 6,
      keyChanged: 7,
    });
  });

  test("no command is a usage error", async () => {
    const { code, err, out } = await datavalv([]);
    expect(code).toBe(cli.EXIT_USAGE);
    expect(err).toContain("usage: datavalv");
    expect(out).toBe("");
  });

  test("an unknown flag is a usage error", async () => {
    const { code, err } = await datavalv(["keygen", "--colour"]);
    expect(code).toBe(cli.EXIT_USAGE);
    expect(err).toContain("--colour");
  });

  test("--help goes to stdout and exits 0", async () => {
    const { code, out, err } = await datavalv(["--help"]);
    expect(code).toBe(cli.EXIT_OK);
    expect(out).toContain("usage: datavalv");
    expect(out).toContain("5  nothing is wrong; run it again later");
    expect(err).toBe("");
  });
});

// ------------------------------------------------------------------ version

describe("version", () => {
  test("every run says which version it is, on stderr", async () => {
    // A bug report that says "the push failed" about an unknown version is
    // not answerable, and the version somebody is running is the one fact
    // nobody thinks to include. stderr, never stdout: stdout here is read by
    // machines -- the README compares `$(datavalv vault key …)` against a
    // fingerprint in a one-line shell test, and a banner turns it false.
    const fake = service();
    const { out, err } = await datavalv(
      ["vault", "retention", "--external-id", EXTERNAL_ID, "--keep", "3", ...connection(keyFile())],
      { fetch: fake.fetch },
    );

    expect(err).toContain(`datavalv ${VERSION}`);
    expect(out.trim()).toBe("3");
    expect(out).not.toContain(VERSION);
  });

  test("--version asked for on its own goes to stdout", async () => {
    // Asked for, so it is the answer rather than a note beside one.
    const { code, out } = await datavalv(["--version"]);

    expect(code).toBe(cli.EXIT_OK);
    expect(out.trim()).toBe(`datavalv ${VERSION}`);
  });
});

// ----------------------------------------------------------------- the help

describe("help", () => {
  test("a command's --help is about that command, not the whole program", async () => {
    // It printed the one usage block for every `--help`, so the answer to
    // "what does vault create do" was a list of five other commands with it.
    // The Python client has had per-command help since it existed, and these
    // two documents make the same promise about the same commands.
    const { code, out } = await datavalv(["vault", "create", "--help"]);

    expect(code).toBe(cli.EXIT_OK);
    expect(out).toContain("--owner-email");
    // Not the whole block: another command's flags being on screen is how a
    // reader ends up scrolling to find the one they asked about.
    expect(out).not.toContain("--idempotency-key");
  });

  test("every command has help of its own", async () => {
    // A command added without one falls back to the program's, which answers
    // a question nobody asked.
    for (const command of Object.keys(cli.COMMAND_OPTIONS) as cli.CommandName[]) {
      const { code, out } = await datavalv([...command.split(" "), "--help"]);

      expect(code, command).toBe(cli.EXIT_OK);
      expect(
        out.split(/\s+/).length,
        `${command} has help thin enough to be a restatement of its one-liner`,
      ).toBeGreaterThan(40);
      expect(out, command).toContain(`datavalv ${command}`);
      // `USAGE` lists every command's synopsis, so a command that fell back
      // to it would satisfy the line above while answering the wrong
      // question. This is the assertion that catches the fallback.
      expect(out.trim(), `${command} falls back to the program's own help`).not.toBe(
        cli.USAGE.trim(),
      );
    }
  });

  test("the program's own help says what order to do things in", async () => {
    // A command list is not a procedure. Three of these happen once, in one
    // order, and one of the steps is not a command at all.
    const { out } = await datavalv(["--help"]);

    expect(out).toContain("/applications");
    for (const step of ["keygen", "vault create", "push"]) {
      expect(out).toContain(step);
    }
  });
});

// -------------------------------------------------------------- vault delete

describe("vault delete", () => {
  test("sends the confirmation and says what went", async () => {
    const fake = service();
    const { code, out, err } = await datavalv(
      [
        "vault",
        "delete",
        "--external-id",
        EXTERNAL_ID,
        "--confirm",
        EXTERNAL_ID,
        ...connection(keyFile()),
      ],
      { fetch: fake.fetch },
    );

    expect(code).toBe(cli.EXIT_OK);
    const call = fake.calls[0]!;
    expect(call.method).toBe("DELETE");
    expect(call.json()).toEqual({ confirm: EXTERNAL_ID });
    expect(out).toContain("t-1");
    expect(err).toContain("copies");
  });

  test("refuses a confirmation that does not match, without calling", async () => {
    // The whole point of the flag, and the reason it is not optional. An
    // operator who types the wrong identifier into one of the two gets a
    // refusal and no request; deriving --confirm from --external-id would
    // make this test impossible to write.
    const fake = service();
    const { code, err } = await datavalv(
      [
        "vault",
        "delete",
        "--external-id",
        EXTERNAL_ID,
        "--confirm",
        "kund-4712",
        ...connection(keyFile()),
      ],
      { fetch: fake.fetch },
    );

    expect(code).toBe(cli.EXIT_USAGE);
    expect(fake.calls).toEqual([]);
    expect(err).toContain("--confirm");
  });

  test("requires the confirmation at all", async () => {
    const fake = service();
    const { code, err } = await datavalv(
      ["vault", "delete", "--external-id", EXTERNAL_ID, ...connection(keyFile())],
      { fetch: fake.fetch },
    );

    expect(code).toBe(cli.EXIT_USAGE);
    expect(fake.calls).toEqual([]);
    expect(err).toContain("--confirm");
  });
});

// ----------------------------------------------------------- vault retention

describe("vault retention", () => {
  test("patches the vault and says when it takes effect", async () => {
    // The number is easy; *when* it applies is the part an operator gets
    // wrong. Nothing is deleted by this call: retention runs when the next
    // copy is confirmed, so an operator who lowered the number to free space
    // and saw nothing happen deserves to read why here.
    const fake = service();
    const { code, out, err } = await datavalv(
      ["vault", "retention", "--external-id", EXTERNAL_ID, "--keep", "12", ...connection(keyFile())],
      { fetch: fake.fetch },
    );

    expect(code).toBe(cli.EXIT_OK);
    const call = fake.calls[0]!;
    expect(call.method).toBe("PATCH");
    expect(call.url.pathname).toBe(`/v1/tenants/${EXTERNAL_ID}`);
    expect(call.json()).toEqual({ retentionCount: 12 });

    expect(out).toContain("12");
    expect(err.toLowerCase()).toContain("next");
  });

  test("refuses a count out of range without spending a call", async () => {
    const fake = service();
    const { code, err } = await datavalv(
      ["vault", "retention", "--external-id", EXTERNAL_ID, "--keep", "0", ...connection(keyFile())],
      { fetch: fake.fetch },
    );

    expect(code).toBe(cli.EXIT_USAGE);
    expect(fake.calls).toEqual([]);
    expect(err).toContain("--keep");
  });
});

// -------------------------------------------------------------- vault create

describe("vault create", () => {
  test("prints the tenant id and sends the body", async () => {
    const fake = service();
    const { code, out } = await datavalv(
      [
        "vault",
        "create",
        "--external-id",
        EXTERNAL_ID,
        "--owner-email",
        "anna@example.se",
        "--name",
        "Kund 4711",
        "--locale",
        "en",
        "--retention",
        "7",
        ...connection(keyFile()),
      ],
      { fetch: fake.fetch },
    );

    expect(code).toBe(cli.EXIT_OK);
    expect(out.trim()).toBe("t-1");
    expect(fake.calls[0]!.json()).toEqual({
      externalId: EXTERNAL_ID,
      ownerEmail: "anna@example.se",
      name: "Kund 4711",
      locale: "en",
      retentionCount: 7,
    });
  });

  test("omits what was not asked for", async () => {
    const fake = service();
    await datavalv(
      [
        "vault",
        "create",
        "--external-id",
        EXTERNAL_ID,
        "--owner-email",
        "anna@example.se",
        ...connection(keyFile()),
      ],
      { fetch: fake.fetch },
    );
    expect(fake.calls[0]!.json()).toEqual({
      externalId: EXTERNAL_ID,
      ownerEmail: "anna@example.se",
    });
  });

  test("warns about the address and the wait", async () => {
    // The one mistake `/connect-system` exists to prevent, said where it is
    // made. A mistyped `ownerEmail` succeeds, mails nobody who will read it,
    // and is reported as an error to no one.
    const fake = service();
    const { err } = await datavalv(
      [
        "vault",
        "create",
        "--external-id",
        EXTERNAL_ID,
        "--owner-email",
        "anna@example.se",
        ...connection(keyFile()),
      ],
      { fetch: fake.fetch },
    );
    expect(err).toContain("anna@example.se");
    expect(err).toContain("tenant_not_initialized");
  });

  test("a retention that is not a whole number is refused by the command line", async () => {
    // `Number("weekly")` is NaN, `JSON.stringify` turns NaN into null, and the
    // service answers 422 for a null it was told forbids unknown values. None
    // of that is an error message anybody can act on, so it is caught here.
    const fake = service();
    const { code, err } = await datavalv(
      [
        "vault",
        "create",
        "--external-id",
        EXTERNAL_ID,
        "--owner-email",
        "anna@example.se",
        "--retention",
        "weekly",
        ...connection(keyFile()),
      ],
      { fetch: fake.fetch },
    );
    expect(code).toBe(cli.EXIT_USAGE);
    expect(err).toContain("--retention");
    expect(fake.calls).toEqual([]);
  });

  test("an unknown locale is refused by the command line", async () => {
    // `sv` and `en` are what the service composes in; a third is a 422. Caught
    // here rather than sent, because the command line can name the choices and
    // the API's answer is `invalid_request` with no field in it.
    const fake = service();
    const { code } = await datavalv(
      [
        "vault",
        "create",
        "--external-id",
        EXTERNAL_ID,
        "--owner-email",
        "anna@example.se",
        "--locale",
        "de",
        ...connection(keyFile()),
      ],
      { fetch: fake.fetch },
    );
    expect(code).toBe(cli.EXIT_USAGE);
    expect(fake.calls).toEqual([]);
  });
});

function b64(text: string): Uint8Array<ArrayBuffer> {
  return new Uint8Array(Buffer.from(text, "base64"));
}

// ------------------------------------------------------ the vault's own key

describe("the vault's own key", () => {
  const pushTo = (fake: FakeDatavalv, file: string) =>
    datavalv(["push", dump(), "--external-id", EXTERNAL_ID, ...connection(file)], {
      fetch: fake.fetch,
    });
  const vaultKey = (fake: FakeDatavalv, file: string, ...extra: string[]) =>
    datavalv(["vault", "key", "--external-id", EXTERNAL_ID, ...extra, ...connection(file)], {
      fetch: fake.fetch,
    });
  const another = async () => (await generateKeypair()).publicKeyPem;

  test("the first push says which key it trusted and how to check, and later ones say nothing", async () => {
    // The one moment the fingerprint is worth a person's attention. A line
    // repeated every night is a line nobody reads, and the night it mattered
    // would look like every other.
    const fake = service();
    const file = keyFile();
    const first = await pushTo(fake, file);
    const second = await pushTo(fake, file);

    const fingerprint = await publicKeyFingerprint(tenantKey.publicKeyPem);
    expect(first.code).toBe(cli.EXIT_OK);
    expect(first.out.trim()).toBe(BACKUP_ID);
    expect(first.err).toContain(fingerprint);
    expect(first.err).toContain("under their backups");
    expect(second.code).toBe(cli.EXIT_OK);
    expect(second.err).not.toContain(fingerprint);
  });

  test("a changed key exits 7, sends nothing and prints no backup id", async () => {
    // Its own code, because it is neither of the neighbours: 5 would have a
    // schedule try again every night against a key that is wrong every night,
    // and 6 says the *service* refused, when it is this client refusing the
    // service.
    const fake = service();
    const file = keyFile();
    await pushTo(fake, file);
    fake.tenantPublicPem = await another();
    fake.uploaded = undefined;

    const { code, out, err } = await pushTo(fake, file);

    expect(code).toBe(cli.EXIT_KEY_CHANGED);
    expect(out).toBe("");
    expect(fake.uploaded).toBeUndefined();
    expect(err).toContain("Nothing was encrypted or sent");
    expect(err).toContain("vault key");
    expect(err).toContain("--forget");
  });

  test("vault key prints the fingerprint and records nothing", async () => {
    // Looking is not trusting. stdout carries the fingerprint alone, so that
    // `[ "$(datavalv vault key …)" = "$FROM_THE_OWNER" ]` is a one-line check.
    const fake = service();
    const file = keyFile();
    const first = await vaultKey(fake, file);
    const second = await vaultKey(fake, file);

    expect(first.code).toBe(cli.EXIT_OK);
    expect(first.out.trim()).toBe(await publicKeyFingerprint(tenantKey.publicKeyPem));
    expect(first.err).toContain("not on record");
    expect(second.err).toContain("not on record");
  });

  test("vault key --trust records the owner's fingerprint without asking the service", async () => {
    // The strongest first use there is. The fingerprint the owner reads out was
    // worked out in their browser from the private key they hold, so a pin made
    // from it never passed through the service at all -- and a substituted key
    // is then refused on the very first push, not the second.
    const fake = service();
    const file = keyFile();
    const fingerprint = await publicKeyFingerprint(tenantKey.publicKeyPem);

    const trusted = await vaultKey(fake, file, "--trust", fingerprint.toUpperCase());
    expect(trusted.code).toBe(cli.EXIT_OK);
    expect(fake.calls).toEqual([]);

    const pushed = await pushTo(fake, file);
    expect(pushed.code).toBe(cli.EXIT_OK);
    expect(pushed.err).not.toContain(fingerprint);

    fake.tenantPublicPem = await another();
    expect((await pushTo(fake, file)).code).toBe(cli.EXIT_KEY_CHANGED);
  });

  test("a substituted key is refused on the first push when the owner's was trusted", async () => {
    const fake = service();
    const file = keyFile();
    expect((await vaultKey(fake, file, "--trust", "ab".repeat(32))).code).toBe(cli.EXIT_OK);

    expect((await pushTo(fake, file)).code).toBe(cli.EXIT_KEY_CHANGED);
    expect(fake.uploaded).toBeUndefined();
  });

  test("vault key --trust refuses something that is not a fingerprint", async () => {
    const { code, err } = await vaultKey(service(), keyFile(), "--trust", "de6272b8");
    expect(code).toBe(cli.EXIT_CONFIG);
    expect(err).toContain("64");
  });

  test("vault key says when the offered key is not the one on record", async () => {
    const fake = service();
    const file = keyFile();
    await pushTo(fake, file);
    expect((await vaultKey(fake, file)).err).toContain("matches");

    fake.tenantPublicPem = await another();
    const { code, err } = await vaultKey(fake, file);
    expect(code).toBe(cli.EXIT_KEY_CHANGED);
    expect(err).toContain("NOT the key on record");
  });

  test("vault key --forget lets a recreated vault be pinned again", async () => {
    const fake = service();
    const file = keyFile();
    await pushTo(fake, file);
    fake.tenantPublicPem = await another();
    expect((await pushTo(fake, file)).code).toBe(cli.EXIT_KEY_CHANGED);

    fake.calls.length = 0;
    expect((await vaultKey(fake, file, "--forget")).code).toBe(cli.EXIT_OK);
    expect(fake.calls).toEqual([]);
    expect((await pushTo(fake, file)).code).toBe(cli.EXIT_OK);
  });

  test("--trust and --forget together are a usage error", async () => {
    const { code } = await vaultKey(service(), keyFile(), "--forget", "--trust", "ab".repeat(32));
    expect(code).toBe(cli.EXIT_USAGE);
  });
});
