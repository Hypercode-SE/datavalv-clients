/**
 * The default pin file is in the user's home directory, SSH-style. No test may
 * read or write the real one: a suite that pinned a fixture key there would
 * make the developer's next real push refuse.
 */
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach } from "vitest";

let directory: string;

beforeEach(() => {
  directory = mkdtempSync(join(tmpdir(), "datavalv-pins-"));
  process.env["DATAVALV_KNOWN_VAULTS"] = join(directory, "known_vaults.json");
});

afterEach(() => {
  rmSync(directory, { recursive: true, force: true });
});
