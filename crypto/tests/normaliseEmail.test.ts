import { readFileSync } from "node:fs";
import { expect, test } from "vitest";
import { normaliseEmail } from "../src/derive.js";

/**
 * Cross-implementation vectors for email normalisation (spec 6.2).
 *
 * `api/tests/test_emails.py` reads this same file. Between them the two
 * languages cannot drift on the string that both salts a master key and
 * decides who owns a tenant -- and both suites run in CI.
 *
 * Code points, never literal text: a file holding literal NFD characters gets
 * silently recomposed by an editor or a JSON tool, and the NFD cases, which
 * are the whole reason the file exists, would then pass without testing
 * anything.
 */
type Case = { name: string; why: string; input: string[]; normalised: string[] };

const vectors = JSON.parse(
  readFileSync(
    new URL("../../format/vectors/v1/email-normalisation.json", import.meta.url),
    "utf8",
  ),
) as { cases: Case[] };

function text(codepoints: string[]): string {
  return codepoints.map((point) => String.fromCodePoint(Number.parseInt(point, 16))).join("");
}

test.each(vectors.cases.map((c) => [c.name, c] as const))(
  "email vector %s",
  (_name, c) => {
    expect(normaliseEmail(text(c.input))).toBe(text(c.normalised));
  },
);

test("the vectors actually carry a decomposed spelling", () => {
  // Without this the suite above could be green because every "NFD" input had
  // been quietly recomposed on the way into the file.
  const decomposed = vectors.cases.filter((c) => text(c.input) !== text(c.input).normalize("NFC"));
  expect(decomposed.length).toBeGreaterThanOrEqual(3);
  for (const c of decomposed) {
    expect(text(c.normalised)).toBe(text(c.normalised).normalize("NFC"));
  }
});
