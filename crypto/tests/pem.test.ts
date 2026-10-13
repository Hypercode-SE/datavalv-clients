import { expect, test } from "vitest";
import { b64decode, b64encode, derToPem, pemToDer } from "../src/pem.js";

test("base64 round trip", () => {
  const bytes = new Uint8Array([0, 1, 250, 255, 128, 64]);
  expect(Array.from(b64decode(b64encode(bytes)))).toEqual(Array.from(bytes));
});

test("base64 of empty input", () => {
  expect(b64encode(new Uint8Array())).toBe("");
  expect(b64decode("").length).toBe(0);
});

test("pem round trip preserves the der bytes", () => {
  const der = new Uint8Array(Array.from({ length: 100 }, (_, i) => i));
  const pem = derToPem(der, "PUBLIC KEY");
  expect(pem.startsWith("-----BEGIN PUBLIC KEY-----")).toBe(true);
  expect(pem.trimEnd().endsWith("-----END PUBLIC KEY-----")).toBe(true);
  expect(Array.from(pemToDer(pem))).toEqual(Array.from(der));
});

test("pem body is wrapped at 64 characters", () => {
  const der = new Uint8Array(200);
  const body = derToPem(der, "PUBLIC KEY").split("\n").slice(1, -2);
  for (const line of body) expect(line.length).toBeLessThanOrEqual(64);
});

test("pemToDer tolerates crlf line endings", () => {
  const der = new Uint8Array([1, 2, 3, 4, 5]);
  const pem = derToPem(der, "PRIVATE KEY").replace(/\n/g, "\r\n");
  expect(Array.from(pemToDer(pem))).toEqual(Array.from(der));
});
