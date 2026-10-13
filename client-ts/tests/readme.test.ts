/**
 * `README.md` as executable documentation.
 *
 * The README is the answer to "how do I connect a server", and it is the reason
 * somebody installs this package at all. It is also prose: nothing compiles it,
 * and the first person to find out that a flag was renamed is an operator whose
 * copied-and-pasted command exited 2 at three in the morning.
 *
 * So the document is the source and this file is the only copy. Every
 * `datavalv` command in it is pulled out of the markdown and handed to the real
 * parser, every environment variable it names is proved to be one the CLI
 * actually reads, its exit-code table is compared against the one the CLI
 * prints, and every name its TypeScript examples tell a reader to type is
 * checked against the object that would have to have it.
 *
 * None of this checks that the *prose* is true. Nothing can. It checks the
 * parts that rot silently, which are the parts a reader types.
 */

import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { describe, expect, test, vi } from "vitest";

import * as cli from "../src/cli.js";
import { DatavalvClient, DatavalvError, KNOWN_VAULTS_ENV, VERSION } from "../src/index.js";
import { API_BASE, CLIENT_ID, EXTERNAL_ID, FakeDatavalv, KEY_ID } from "./support/fakeDatavalv.js";
import { signingKey, tenantKey } from "./support/fixtures.js";

const README = fs.readFileSync(path.join(import.meta.dirname, "..", "README.md"), "utf8");
const RELEASING = fs.readFileSync(
  path.join(import.meta.dirname, "..", "RELEASING.md"),
  "utf8",
);

function codeBlocks(text: string): string[] {
  return [...text.matchAll(/^```[a-z]*\n(.*?)^```/gms)].map((match) => match[1]!);
}

/**
 * `[line, argv]` for every `datavalv …` invocation in a code block.
 *
 * The last segment of a pipeline is taken, which is what makes the
 * `pg_dump … | datavalv push -` example in step 6 a real assertion rather than
 * a line this parser skips.
 */
function datavalvCommands(text: string): [string, string[]][] {
  const found: [string, string[]][] = [];
  for (const block of codeBlocks(text)) {
    for (const rawLine of block.split("\n")) {
      const command = rawLine.split("|").pop()!.trim();
      if (!command.startsWith("datavalv ")) continue;
      found.push([command, tokenise(command).slice(1)]);
    }
  }
  return found;
}

/** Enough of a shell word-splitter for `--name "Kund 4711"`. */
function tokenise(line: string): string[] {
  const tokens: string[] = [];
  const pattern = /"([^"]*)"|'([^']*)'|(\S+)/g;
  for (const match of line.matchAll(pattern)) {
    tokens.push(match[1] ?? match[2] ?? match[3]!);
  }
  return tokens;
}

// ------------------------------------------------------------------ commands

describe("the commands it shows", () => {
  test("it shows commands at all", () => {
    // The guard under the guard: a README that stopped containing commands
    // would make every test below pass by having nothing to check.
    const commands = datavalvCommands(README);
    expect(commands.map(([line]) => line).length).toBeGreaterThanOrEqual(3);
  });

  test("every command in the README parses", () => {
    for (const [line, argv] of datavalvCommands(README)) {
      expect(
        () => cli.parseCommandLine(argv),
        `README command does not parse: ${line}`,
      ).not.toThrow();
    }
  });

  test("the README shows every command the CLI has", () => {
    // A command added without a line in the README is a command nobody finds.
    const documented = new Set(
      datavalvCommands(README).map(([, argv]) => cli.parseCommandLine(argv).command),
    );
    // The CLI's own table, not a list kept by hand beside it: the literal
    // that used to be here had to be updated for every new command, so a
    // command added without a README line left this passing -- which is the
    // one thing it exists to catch.
    expect(documented).toEqual(new Set(Object.keys(cli.COMMAND_OPTIONS) as cli.CommandName[]));
  });

  test("the releasing commands name the version being released", () => {
    // The defect this catches shipped and sat there through two releases: the
    // build, inspect and tag commands in RELEASING.md all still said 0.1.0, a
    // version that was never published, because nobody bumping a release
    // thinks to reread the file telling them how to bump a release. Copying
    // any of them does the wrong thing quietly — `tar -tzf` on a tarball that
    // is not there, a tag that publishes a version the repository does not
    // declare.
    //
    // Prose is exempt on purpose. "0.5.1 took about five minutes to appear"
    // is a record of what happened, and a record that rewrote itself every
    // release would be worth nothing.
    const stale = new Set(
      codeBlocks(RELEASING)
        .flatMap((block) => [...block.matchAll(/\b\d+\.\d+\.\d+\b/g)].map((m) => m[0]))
        .filter((found) => found !== VERSION),
    );

    expect([...stale], `RELEASING.md commands name versions other than ${VERSION}`).toEqual([]);
  });

  test("the install lines name the tarball this version builds", () => {
    // The install line names a file. A version bump that misses it leaves a
    // command that fails for whoever copies it.
    const filenames = [...README.matchAll(/datavalv-client-([0-9][^-]*)\.tgz/g)].map(
      (match) => match[1]!,
    );
    expect(filenames.length, "the README no longer shows a tarball to install").toBeGreaterThan(0);
    expect(new Set(filenames)).toEqual(new Set([VERSION]));
  });

  test("it shows the install line, and sends nobody to a repository they cannot open", () => {
    // This test used to assert the opposite -- that no `npm install
    // @datavalv/...` line appeared anywhere, and that the prose said "is not on
    // npm" -- because nothing had been published and a convenient-looking
    // snippet would have 404'd for everyone who copied it. Publishing inverts
    // the first half: the install line is now the first thing a reader needs.
    const installs = codeBlocks(README).flatMap((block) =>
      block.split("\n").filter((line) => /^npm install\s+@datavalv\/client$/.test(line.trim())),
    );
    expect(installs.length, "the README no longer shows how to install it").toBeGreaterThan(0);

    // The half worth keeping, pointed somewhere new. `Hypercode-SE/datavalv` is
    // the private monorepo; the only readers of this file are on npm and on the
    // public mirror, and for every one of them a clone of it fails. The
    // lookahead lets `datavalv-clients` through and nothing else.
    expect(
      README,
      "this README is published to npm; the monorepo is private and a clone of it 404s there",
    ).not.toMatch(/github\.com\/Hypercode-SE\/datavalv(?![-\w])/);
  });
});

// ------------------------------------------------------------------- library

describe("the library it documents", () => {
  test("every name the examples import is exported", async () => {
    const imported = new Set<string>();
    for (const match of README.matchAll(/import\s*\{([^}]*)\}\s*from\s*"@datavalv\/client"/g)) {
      for (const name of match[1]!.split(",")) {
        const cleaned = name.trim().replace(/^type\s+/, "");
        if (cleaned) imported.add(cleaned);
      }
    }
    expect(imported.size, "the README imports nothing from @datavalv/client").toBeGreaterThan(0);

    const surface = await import("../src/index.js");
    for (const name of imported) {
      expect(Object.keys(surface), `the README imports ${name}`).toContain(name);
    }
  });

  test("every member the examples call exists on the object that must have it", async () => {
    // A renamed method in a README is a copied snippet that throws
    // `TypeError: client.pushBackup is not a function` in somebody's cron job.
    //
    // `pushed` is checked against a real result rather than against a type:
    // `PushedBackup` is an interface and has no runtime shape, so the only
    // honest source for its field names is a push that actually happened.
    const fake = new FakeDatavalv({
      signingPublicPem: signingKey.publicKeyPem,
      tenantPublicPem: tenantKey.publicKeyPem,
    });
    const client = new DatavalvClient({
      apiBase: API_BASE,
      clientId: CLIENT_ID,
      keyId: KEY_ID,
      privateKey: signingKey.privateKeyPem,
      fetch: fake.fetch,
    });
    const pushed = await client.pushBackup(EXTERNAL_ID, new Uint8Array([1, 2, 3]));
    const vault = await client.createVault(EXTERNAL_ID, "anna@example.se");

    const owners: [string, Set<string>][] = [
      ["client", new Set(Object.getOwnPropertyNames(DatavalvClient.prototype))],
      ["pushed", new Set(Object.keys(pushed))],
      ["vault", new Set(Object.keys(vault))],
      ["error", new Set(["retryable", "message", "name", "step", "status", "code", "detail"])],
    ];

    let seen = 0;
    for (const [variable, available] of owners) {
      // Digits belong to the name: `pushed.sha256` truncated to `sha` would be
      // a test asserting against a field nobody wrote.
      for (const match of README.matchAll(new RegExp(`\\b${variable}\\.([A-Za-z_0-9]+)`, "g"))) {
        const member = match[1]!;
        expect(available, `the README uses ${variable}.${member}`).toContain(member);
        seen += 1;
      }
    }
    expect(seen, "the README stopped showing the library's surface").toBeGreaterThanOrEqual(5);
    expect(new DatavalvError("x").retryable).toBe(false);
  });
});

// ------------------------------------------------------------------ settings

describe("the settings it names", () => {
  test("every variable is one the CLI reads, by name", async () => {
    // Each one is removed in turn, and the CLI has to miss it **by name**.
    //
    // This is stronger than comparing two lists: it fails both for a variable
    // the README invents and for one the CLI stopped reading, and it does it
    // through the code path an operator meets — `datavalv push` with the
    // configuration incomplete, which exits 3 before a single request is made.
    //
    // The message matters as much as the code. A variable this client never
    // reads would leave the other three in place, the command would fail three
    // lines later for an unrelated reason, and exit 3 all the same.
    const everything = new Set([...README.matchAll(/\bDATAVALV_[A-Z_]+\b/g)].map((m) => m[0]));
    // One variable is optional and so cannot be "missed by name": where the
    // vault-key pins are kept. It is checked against the module that reads it
    // rather than against a failure, and `pins.test.ts` proves it is honoured.
    expect(everything.has(KNOWN_VAULTS_ENV), "the README no longer says where the pins are kept").toBe(
      true,
    );
    everything.delete(KNOWN_VAULTS_ENV);
    const named = [...everything].sort();
    expect(named.length, "the README no longer documents any settings").toBeGreaterThan(0);

    // Outside the checkout: this writes a PEM, and a crashed run must not
    // leave one inside a repository whose .gitignore is the only thing
    // standing between a key file and a commit.
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "datavalv-readme-"));
    try {
      const key = path.join(tmp, "datavalv-signing.pem");
      fs.writeFileSync(key, signingKey.privateKeyPem, { mode: 0o600 });
      fs.chmodSync(key, 0o600);
      const dump = path.join(tmp, "dump.sql.gz");
      fs.writeFileSync(dump, "-- a dump\n");

      const complete: Record<string, string> = {
        DATAVALV_API: "https://api.datavalv.se",
        DATAVALV_CLIENT_ID: CLIENT_ID,
        DATAVALV_KEY_ID: KEY_ID,
        DATAVALV_PRIVATE_KEY: key,
      };
      expect(named).toEqual(Object.keys(complete).sort());

      for (const missing of named) {
        const before = { ...process.env };
        for (const name of named) delete process.env[name];
        for (const [name, value] of Object.entries(complete)) {
          if (name !== missing) process.env[name] = value;
        }

        const stderr: string[] = [];
        const spy = vi
          .spyOn(process.stderr, "write")
          .mockImplementation((chunk) => (stderr.push(String(chunk)), true));
        let code: number;
        try {
          code = await cli.main(["push", dump, "--external-id", EXTERNAL_ID]);
        } finally {
          spy.mockRestore();
          for (const name of named) delete process.env[name];
          for (const name of named) {
            const value = before[name];
            if (value !== undefined) process.env[name] = value;
          }
        }

        expect(code, `${missing} missing should be a configuration failure`).toBe(
          cli.EXIT_CONFIG,
        );
        expect(
          stderr.join(""),
          `the README names ${missing}, and leaving it out is not what the CLI complained about`,
        ).toContain(`set ${missing}`);
      }
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  test("it says the key setting is a path, and why", () => {
    // The one settings mistake with a cost. `readPrivateKey` refuses a PEM in
    // `DATAVALV_PRIVATE_KEY` and refuses to echo it back, and from the outside
    // that looks like an unhelpful client unless the document that sent the
    // operator there says what it is for. The wrapping is normalised away
    // first: this is about what the README says, not where its lines break.
    const prose = README.split(/\s+/).join(" ");
    expect(prose).toContain("the **path** to the key");
    for (const reason of ["in `ps`", "shell history", "crash dump"]) {
      expect(prose, `the README no longer says why: ${reason}`).toContain(reason);
    }
  });
});

// ---------------------------------------------------------------- exit codes

describe("the exit codes it lists", () => {
  function readmeExitCodes(text: string): Map<number, string> {
    const rows = new Map<number, string>();
    for (const match of text.matchAll(/^\|\s*(\d)\s*\|\s*(.+?)\s*\|$/gm)) {
      rows.set(Number(match[1]), match[2]!.trim());
    }
    return rows;
  }

  function cliExitCodes(): Map<number, string> {
    const rows = new Map<number, string>();
    for (const line of cli.EXIT_TABLE.split("\n").slice(1)) {
      const [code, description] = line.trim().split(/\s\s+/, 2);
      rows.set(Number(code), description!.trim());
    }
    return rows;
  }

  test("the table is the CLI's own", () => {
    // A schedule branches on these numbers. The README and `--help` disagreeing
    // about what 5 means is the defect that gets somebody paged for a vault
    // whose owner simply has not signed in yet.
    expect(readmeExitCodes(README)).toEqual(cliExitCodes());
  });

  test("the documented codes are the constants the CLI returns", () => {
    const documented = readmeExitCodes(README);
    expect(new Set(documented.keys())).toEqual(
      new Set([
        cli.EXIT_OK,
        cli.EXIT_FAILED,
        cli.EXIT_USAGE,
        cli.EXIT_CONFIG,
        cli.EXIT_AUTH,
        cli.EXIT_RETRY,
        cli.EXIT_REFUSED,
        cli.EXIT_KEY_CHANGED,
      ]),
    );
    expect(documented.get(cli.EXIT_RETRY)).toContain("run it again later");
  });
});
