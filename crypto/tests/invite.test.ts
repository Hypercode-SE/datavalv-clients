import { readFileSync } from "node:fs";
import { describe, expect, it, test } from "vitest";

import { deriveInviteKey } from "../src/invite.js";
import { hkdf } from "../src/derive.js";
import { HKDF_INFO } from "../src/formatConstants.js";

describe("deriveInviteKey", () => {
  it("is 32 bytes and deterministic", async () => {
    const secret = new Uint8Array(32).fill(7) as Uint8Array<ArrayBuffer>;
    const once = await deriveInviteKey(secret);
    const twice = await deriveInviteKey(secret);
    expect(once.byteLength).toBe(32);
    expect(Array.from(once)).toEqual(Array.from(twice));
  });

  it("is not the secret it came from", async () => {
    const secret = new Uint8Array(32).fill(7) as Uint8Array<ArrayBuffer>;
    const key = await deriveInviteKey(secret);
    // The secret travels in a URL fragment; the key opens the vault. If they
    // were the same value, a fragment in a browser history entry would be the
    // vault key rather than one step away from it.
    expect(Array.from(key)).not.toEqual(Array.from(secret));
  });

  it("is separated from every other derivation by its info string alone", async () => {
    // Same HKDF, same input keying material, same output length: the only
    // thing standing between these values is the info string, so dropping or
    // confusing the info is the only way to make this fail.
    //
    // Comparing against deriveRecoveryKey instead would not test that. A
    // recovery code is 160 bits of entirely different bytes, so those two
    // outputs differ whatever info string either side uses -- the assertion
    // would stay green with the info dropped altogether.
    const secret = new Uint8Array(32).fill(7) as Uint8Array<ArrayBuffer>;
    const invite = await deriveInviteKey(secret);
    for (const info of [HKDF_INFO.recovery, HKDF_INFO.kek, HKDF_INFO.login, ""]) {
      const other = await hkdf(secret, info, 32);
      expect(Array.from(invite)).not.toEqual(Array.from(other));
    }
  });

  it("uses the info string the frozen spec pins", () => {
    expect(HKDF_INFO.invite).toBe("datavalv/invite/v1");
  });
});

/**
 * The cross-language vector.
 *
 * `client/tests/test_invite_key.py` reads this same file and
 * `scripts/conformance_matrix.py` pipes it through both conformance CLIs, so a
 * derivation that drifted in one language and not the other cannot merge.
 *
 * Hex on both sides, never a typed literal: a fixture and its expected value
 * have twice become the same bytes on this project because an editor
 * normalised a typed non-ASCII character, leaving a test comparing a string to
 * itself.
 */
type InviteCase = { name: string; secretHex: string; inviteKeyHex: string };

const inviteVectors = JSON.parse(
  readFileSync(new URL("../../format/vectors/v1/invite-key.json", import.meta.url), "utf8"),
) as { info: string; lengthBytes: number; cases: InviteCase[] };

function fromHex(hex: string): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i += 1) out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out as Uint8Array<ArrayBuffer>;
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

test("the vector file describes the derivation this package performs", () => {
  expect(inviteVectors.info).toBe(HKDF_INFO.invite);
  expect(inviteVectors.lengthBytes).toBe(32);
  expect(inviteVectors.cases.length).toBeGreaterThanOrEqual(3);
});

test.each(inviteVectors.cases.map((c) => [c.name, c] as const))(
  "invite-key vector %s: reproduces the pinned key",
  async (_name, c) => {
    expect(c.secretHex).toHaveLength(64);
    const key = await deriveInviteKey(fromHex(c.secretHex));
    expect(toHex(key)).toBe(c.inviteKeyHex);
  },
);
