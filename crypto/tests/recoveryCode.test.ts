import { expect, test } from "vitest";
import {
  CROCKFORD_ALPHABET,
  formatRecoveryCode,
  generateRecoveryCode,
  recoveryCodeToBytes,
} from "../src/recoveryCode.js";

test("alphabet excludes the letters people misread", () => {
  // Crockford base32 drops I, L, O and U: the first three collide with 1 and 0
  // when read off paper, and U is dropped to avoid accidental obscenities.
  for (const letter of ["I", "L", "O", "U"]) {
    expect(CROCKFORD_ALPHABET).not.toContain(letter);
  }
  expect(CROCKFORD_ALPHABET.length).toBe(32);
});

test("a generated code is four groups of eight", () => {
  const code = generateRecoveryCode();
  const groups = code.split("-");
  expect(groups).toHaveLength(4);
  for (const group of groups) expect(group).toHaveLength(8);
});

test("a generated code carries 160 bits", () => {
  expect(recoveryCodeToBytes(generateRecoveryCode()).length).toBe(20);
});

test("round trip through bytes and back", () => {
  const code = generateRecoveryCode();
  expect(formatRecoveryCode(recoveryCodeToBytes(code))).toBe(code);
});

test("two generated codes differ", () => {
  expect(generateRecoveryCode()).not.toBe(generateRecoveryCode());
});

test("decoding accepts lowercase and missing hyphens", () => {
  const code = generateRecoveryCode();
  const sloppy = code.toLowerCase().replaceAll("-", "");
  expect(Array.from(recoveryCodeToBytes(sloppy))).toEqual(
    Array.from(recoveryCodeToBytes(code)),
  );
});

test("decoding maps the characters people actually mistype", () => {
  // Someone reading a printed code will type O for 0 and I or L for 1. Crockford
  // specifies those substitutions, and refusing them would strand a user holding
  // the correct code.
  const canonical = recoveryCodeToBytes("00000000-00000000-00000000-00000000");
  expect(Array.from(recoveryCodeToBytes("OOOOOOOO-OOOOOOOO-OOOOOOOO-OOOOOOOO"))).toEqual(
    Array.from(canonical),
  );
  const ones = recoveryCodeToBytes("11111111-11111111-11111111-11111111");
  expect(Array.from(recoveryCodeToBytes("IIIIIIII-LLLLLLLL-IIIIIIII-LLLLLLLL"))).toEqual(
    Array.from(ones),
  );
});

test("a code of the wrong length is refused", () => {
  expect(() => recoveryCodeToBytes("TOOSHORT")).toThrow(/32 characters/);
});

test("a code containing an invalid character is refused", () => {
  const bad = "UUUUUUUU-UUUUUUUU-UUUUUUUU-UUUUUUUU";
  expect(() => recoveryCodeToBytes(bad)).toThrow(/invalid character/);
});
