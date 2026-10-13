import { describe, expect, test } from "vitest";
import { HEADER_LENGTH, IV_LENGTH } from "../src/formatConstants.js";
import { FormatError, decodeHeader, encodeHeader } from "../src/format.js";
import type { Bytes } from "../src/crypto.js";

const IV = new Uint8Array(Array.from({ length: IV_LENGTH }, (_, i) => i));

test("encoded header has the specified layout", () => {
  const h = encodeHeader(IV);
  expect(h.length).toBe(HEADER_LENGTH);
  expect(Array.from(h.slice(0, 4))).toEqual([0x44, 0x56, 0x4c, 0x56]); // "DVLV"
  expect(h[4]).toBe(1);
  expect(h[5]).toBe(1);
  expect(Array.from(h.slice(6, 8))).toEqual([0, 0]);
  expect(h[8]).toBe(IV_LENGTH);
  expect(Array.from(h.slice(9, 21))).toEqual(Array.from(IV));
});

test("decode returns the iv that was encoded", () => {
  expect(Array.from(decodeHeader(encodeHeader(IV)))).toEqual(Array.from(IV));
});

test("decode ignores trailing ciphertext", () => {
  const blob = new Uint8Array([...encodeHeader(IV), 1, 2, 3, 4]);
  expect(Array.from(decodeHeader(blob))).toEqual(Array.from(IV));
});

test("encode rejects a wrong iv length", () => {
  expect(() => encodeHeader(new Uint8Array(5))).toThrow(/iv length/);
});

describe("malformed headers are rejected", () => {
  const cases: [string, (h: Bytes) => Bytes, RegExp][] = [
    ["bad magic", (h) => { const c = h.slice(); c[0] = 0x58; return c; }, /magic/],
    ["unknown version", (h) => { const c = h.slice(); c[4] = 2; return c; }, /version/],
    ["unknown algorithm", (h) => { const c = h.slice(); c[5] = 9; return c; }, /algorithm/],
    ["reserved not zero", (h) => { const c = h.slice(); c[7] = 1; return c; }, /reserved/],
    ["bad iv length", (h) => { const c = h.slice(); c[8] = 16; return c; }, /iv length/],
    ["truncated", (h) => h.slice(0, 10), /truncated/],
  ];

  test.each(cases)("%s", (_name, mutate, message) => {
    expect(() => decodeHeader(mutate(encodeHeader(IV)))).toThrow(FormatError);
    expect(() => decodeHeader(mutate(encodeHeader(IV)))).toThrow(message);
  });
});
