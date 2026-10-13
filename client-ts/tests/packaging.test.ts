/**
 * The package as somebody else receives it: packed, installed, and run from the
 * install rather than from this checkout.
 *
 * Everything else in this suite imports from `src/`, where every file is
 * present because git says so. A tarball is a different question — it contains
 * what `files` and the build decided to put in it — and the ways that goes
 * wrong are silent:
 *
 * * **`dist/` is built, not committed.** A package whose `main` names a file
 *   the tarball does not carry installs cleanly and throws
 *   `ERR_MODULE_NOT_FOUND` on the first import.
 * * **A `file:` dependency in a published manifest is not an error.** npm
 *   installs the package, prints a warning nobody reads, and simply leaves the
 *   dependency out — so the first thing a user sees is a missing module from a
 *   package that installed successfully. That is the one this project would
 *   walk into, because `@datavalv/crypto` is a sibling directory here.
 *
 * So this packs the real tarballs with the real command and installs them into
 * a directory that has nothing else in it. `datavalv --help` run from there is
 * the whole claim a release makes.
 */

import { execFile } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";

import { afterAll, beforeAll, describe, expect, test } from "vitest";

import { VERSION } from "../src/index.js";

const run = promisify(execFile);

const CLIENT = path.resolve(import.meta.dirname, "..");
const CRYPTO = path.resolve(CLIENT, "..", "crypto");
const REPO_ROOT = path.resolve(CLIENT, "..");

interface Manifest {
  name: string;
  version: string;
  license?: string;
  private?: boolean;
  main?: string;
  types?: string;
  bin?: Record<string, string>;
  files?: string[];
  engines?: Record<string, string>;
  exports?: Record<string, unknown>;
  repository?: { url?: string; directory?: string };
  dependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
}

let workspace: string;
let clientTarball: string;
let cryptoTarball: string;
let install: string;
let installedKey: string | undefined;

beforeAll(async () => {
  workspace = fs.mkdtempSync(path.join(os.tmpdir(), "datavalv-pack-"));
  // `npm pack` runs `prepare`, so these are built from the current source
  // rather than from whatever happens to be in `dist/`.
  cryptoTarball = await pack(CRYPTO);
  clientTarball = await pack(CLIENT);

  install = path.join(workspace, "install");
  fs.mkdirSync(install);
  await run("npm", ["init", "-y"], { cwd: install });
  // Both tarballs, because `@datavalv/crypto` is a peer dependency and is not
  // on a registry for npm to fetch. Once it is published, a consumer gets it
  // automatically; here it is handed over by hand.
  await run("npm", ["install", clientTarball, cryptoTarball], { cwd: install });
}, 300_000);

/**
 * One keypair, made by the installed command, shared by the tests that need it.
 *
 * Made on demand rather than in `beforeAll` so that a tarball missing `dist/`
 * fails the test that inspects the tarball — by name — instead of killing the
 * whole file in a hook whose error says only that a command exited non-zero.
 */
async function installedKeyPem(): Promise<string> {
  if (installedKey === undefined) {
    installedKey = path.join(workspace, "installed-signing.pem");
    await run(path.join(install, "node_modules", ".bin", "datavalv"), [
      "keygen",
      "--out",
      installedKey,
    ], { cwd: install });
  }
  return fs.readFileSync(installedKey, "utf8");
}

afterAll(() => {
  fs.rmSync(workspace, { recursive: true, force: true });
});

async function pack(directory: string): Promise<string> {
  const { stdout } = await run("npm", ["pack", "--pack-destination", workspace], {
    cwd: directory,
    maxBuffer: 16 * 1024 * 1024,
  });
  const name = stdout.trim().split("\n").pop()!;
  return path.join(workspace, name);
}

async function entries(tarball: string): Promise<string[]> {
  const { stdout } = await run("tar", ["-tzf", tarball], { maxBuffer: 16 * 1024 * 1024 });
  return stdout
    .trim()
    .split("\n")
    .map((line) => line.replace(/^package\//, ""));
}

async function manifest(tarball: string): Promise<Manifest> {
  const { stdout } = await run("tar", ["-xzOf", tarball, "package/package.json"], {
    maxBuffer: 16 * 1024 * 1024,
  });
  return JSON.parse(stdout) as Manifest;
}

// ------------------------------------------------------------------ contents

describe("what the tarball carries", () => {
  test("every file main, types and bin name", async () => {
    // Named one by one rather than counted, so a file that stops being shipped
    // is reported by name.
    const shipped = new Set(await entries(clientTarball));
    for (const name of [
      "dist/index.js",
      "dist/index.d.ts",
      "dist/bin.js",
      "dist/cli.js",
      "dist/client.js",
      "dist/errors.js",
      "dist/keys.js",
      "dist/tokens.js",
      "LICENSE",
      "README.md",
      "CHANGELOG.md",
    ]) {
      expect(shipped, `${name} is missing from the tarball`).toContain(name);
    }
  });

  test("the bin has a shebang, which is what makes it runnable", async () => {
    const { stdout } = await run("tar", ["-xzOf", clientTarball, "package/dist/bin.js"]);
    expect(stdout.startsWith("#!/usr/bin/env node")).toBe(true);
  });

  test("no test, config or source-of-truth clutter", async () => {
    const shipped = await entries(clientTarball);
    expect(shipped.filter((name) => name.startsWith("tests/"))).toEqual([]);
    expect(shipped).not.toContain("vitest.config.ts");
    expect(shipped).not.toContain("node_modules");
  });
});

// ------------------------------------------------------------------ metadata

describe("the manifest an index and a reader see", () => {
  test("no dependency npm cannot resolve from a registry", async () => {
    // The defect this file's header describes. A `file:` spec here is not an
    // install error: npm adds the package, warns, and omits the dependency —
    // and the failure surfaces as a missing module in somebody else's cron job.
    const packed = await manifest(clientTarball);
    const specs = Object.entries({
      ...packed.dependencies,
      ...packed.peerDependencies,
    });
    expect(specs.length).toBeGreaterThan(0);
    for (const [name, spec] of specs) {
      expect(spec, `${name} is declared as ${spec}, which no registry can serve`).not.toMatch(
        /^(file:|link:|\.\.?\/)/,
      );
    }
    // `@datavalv/crypto` in particular, because it is the sibling directory
    // that makes the mistake natural.
    expect(packed.peerDependencies?.["@datavalv/crypto"]).toBe("^0.7.0");
  });

  test("licence, repository and engines", async () => {
    const packed = await manifest(clientTarball);
    expect(packed.license).toBe("MIT");
    expect(packed.private).toBeUndefined();
    expect(packed.engines?.["node"]).toBe(">=22");
    expect(packed.repository?.url).toContain("github.com/Hypercode-SE/datavalv");
    expect(packed.repository?.directory).toBe("client-ts");
    expect(packed.exports?.["."]).toEqual({
      types: "./dist/index.d.ts",
      default: "./dist/index.js",
    });
  });

  test("the LICENSE is the MIT one, naming Hypercode AB", async () => {
    const { stdout } = await run("tar", ["-xzOf", clientTarball, "package/LICENSE"]);
    expect(stdout).toContain("MIT License");
    expect(stdout).toContain("Hypercode AB");
  });

  test("one version in two places", async () => {
    // `package.json` and the exported `VERSION`, both hand-maintained, and the
    // one a user ends up with is the tarball's. `RELEASING.md` says to bump
    // both, which is exactly the kind of instruction this test enforces.
    const packed = await manifest(clientTarball);
    expect(VERSION).toBe(packed.version);
    expect(path.basename(clientTarball)).toBe(`datavalv-client-${packed.version}.tgz`);
  });
});

// ------------------------------------------------- the crypto package's half

describe("@datavalv/crypto is publishable too", () => {
  test("it is not private, and its entry points are built output", async () => {
    // It shipped `main: "src/index.ts"` and `private: true`, which works inside
    // this repository and nowhere else: a `.ts` entry point is a file Node
    // cannot load, so `@datavalv/client` would be uninstallable.
    const packed = await manifest(cryptoTarball);
    expect(packed.private).toBeUndefined();
    expect(packed.license).toBe("MIT");
    expect(packed.main).toBe("./dist/index.js");
    expect(packed.types).toBe("./dist/index.d.ts");

    const shipped = new Set(await entries(cryptoTarball));
    expect(shipped).toContain("dist/index.js");
    expect(shipped).toContain("dist/index.d.ts");
    expect(shipped).toContain("LICENSE");
  });
});

// ------------------------------------------------------------------ installed

describe("from the install", () => {
  test("the datavalv command runs, and carries its exit-code table", async () => {
    const datavalv = path.join(install, "node_modules", ".bin", "datavalv");
    expect(fs.existsSync(datavalv), "the tarball installed no `datavalv` command").toBe(true);

    const { stdout } = await run(datavalv, ["--help"], { cwd: install });
    expect(stdout).toContain("usage: datavalv");
    for (const command of ["keygen", "vault", "push"]) expect(stdout).toContain(command);
    // The exit-code table is part of `--help` on purpose: an operator reading a
    // failure at 3am should not have to find the README.
    expect(stdout).toContain("5  nothing is wrong; run it again later");
  });

  test("keygen from the install still writes the key at 0600", async () => {
    // The promise `datavalv keygen` makes is about the mode on disk, and a
    // build that shipped a different `keys.js` would break it where no unit
    // test in this package is looking.
    const pem = await installedKeyPem();
    expect(fs.statSync(installedKey!).mode & 0o777).toBe(0o600);
    expect(pem).toContain("PRIVATE KEY");
  });

  test("the package imports from the install and not from this tree", async () => {
    // The import that a missing `dist/` breaks, run where the source tree
    // cannot answer for it — and the one that proves the peer dependency on
    // `@datavalv/crypto` really was satisfied, since `client.js` imports it at
    // module scope.
    const program =
      "import { DatavalvClient, VERSION } from '@datavalv/client';" +
      "console.log(import.meta.resolve('@datavalv/client'));" +
      "console.log(VERSION);" +
      "console.log(typeof DatavalvClient);";
    const { stdout } = await run(process.execPath, ["--input-type=module", "-e", program], {
      cwd: install,
    });
    const [resolved, version, kind] = stdout.trim().split("\n");

    expect(resolved!.startsWith(`file://${install}`), `resolved to ${resolved}`).toBe(true);
    expect(resolved).not.toContain(REPO_ROOT + path.sep + "client-ts" + path.sep + "src");
    expect(version).toBe(VERSION);
    expect(kind).toBe("function");
  });

  test("a push from the install encrypts with the installed crypto", async () => {
    // End to end through the tarballs: the format code that runs is the one in
    // `@datavalv/crypto`'s `dist/`, not the TypeScript this checkout compiles
    // on the fly.
    const program = `
      import { generateKeypair, unwrapDek, decrypt } from '@datavalv/crypto';
      import { DatavalvClient } from '@datavalv/client';
      const tenant = await generateKeypair();
      const plaintext = new TextEncoder().encode('installed-and-working');
      let registered, uploaded;
      const client = new DatavalvClient({
        apiBase: 'https://example.invalid',
        clientId: 'c', keyId: 'k',
        privateKey: process.env.SIGNING_KEY,
        fetch: async (url, init) => {
          const path = new URL(url).pathname;
          if (path.endsWith('/public-key')) {
            return Response.json({ keyId: 'tk', publicKeyPem: tenant.publicKeyPem });
          }
          if (path.endsWith('/backups')) {
            registered = JSON.parse(init.body);
            return Response.json({ backupId: 'b1', uploadUrl: 'https://example.invalid/put' });
          }
          if (path === '/put') { uploaded = init.body; return new Response(null, { status: 200 }); }
          return Response.json({ status: 'available', pruned: 0 });
        },
      });
      await client.pushBackup('kund-4711', plaintext, { name: 'dump.sql.gz' });
      const dek = await unwrapDek(Buffer.from(registered.wrappedDekB64, 'base64'), tenant.privateKeyPem);
      console.log(Buffer.from(await decrypt(uploaded, dek)).toString('utf8'));
    `;
    const { stdout } = await run(process.execPath, ["--input-type=module", "-e", program], {
      cwd: install,
      env: { ...process.env, SIGNING_KEY: await installedKeyPem() },
    });
    expect(stdout.trim()).toBe("installed-and-working");
  });
});
