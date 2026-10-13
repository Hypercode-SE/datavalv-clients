/**
 * `datavalv keygen`, run with the safety net cut and the floor removed.
 *
 * This is a child process on purpose. It sets `umask(0)` and replaces the
 * `chmod` tidy-up in `keys.ts` with a no-op, which leaves the mode passed to
 * `open` as the only thing that can produce 0600 — the whole question the test
 * that spawns this exists to answer. Neither change is safe to make in the
 * shared test process: a umask is per-process state every other test would
 * inherit, and a neutered `chmod` would stay neutered.
 *
 * Patching works because `keys.ts` imports the DEFAULT export of `node:fs`
 * rather than the `node:fs/promises` namespace. An ES module namespace object
 * is immutable; `fs.promises` is an ordinary object.
 */

import fs from "node:fs";

import { main } from "../../src/cli.js";

process.umask(0o000);

const noop = async (): Promise<void> => {};
fs.promises.chmod = noop as unknown as typeof fs.promises.chmod;
fs.chmodSync = (() => {}) as typeof fs.chmodSync;

const [out, ...rest] = process.argv.slice(2);
if (out === undefined) {
  process.stderr.write("usage: keygenUnderPermissiveUmask.ts OUTPATH [--force]\n");
  process.exitCode = 2;
} else {
  main(["keygen", "--out", out, ...rest]).then((code) => {
    process.exitCode = code;
  });
}
