import { expect, test } from "vitest";
import { ARGON2ID, HKDF_INFO, LOGIN_HASH_PREFIX } from "../src/formatConstants.js";
import {
  deriveLoginHash,
  deriveMasterKey,
  deriveRecoveryKey,
  deriveSalt,
  deriveUserKek,
  normaliseEmail,
} from "../src/derive.js";

const EMAIL = "Anna.Lindqvist@Example.SE";
const PASSWORD = "correct horse battery staple";

test("email normalisation is case-insensitive and trims", () => {
  expect(normaliseEmail("  Anna@Example.SE ")).toBe("anna@example.se");
});

test("the salt is deterministic, so no salt lookup endpoint is needed", async () => {
  const a = await deriveSalt(EMAIL);
  const b = await deriveSalt("anna.lindqvist@example.se");
  expect(Array.from(a)).toEqual(Array.from(b));
  expect(a.length).toBe(32);
});

test("different emails salt differently", async () => {
  const a = await deriveSalt("a@example.se");
  const b = await deriveSalt("b@example.se");
  expect(Array.from(a)).not.toEqual(Array.from(b));
});

test("the master key is 32 bytes and reproducible", async () => {
  const first = await deriveMasterKey(PASSWORD, EMAIL);
  const second = await deriveMasterKey(PASSWORD, EMAIL);
  expect(first.length).toBe(32);
  expect(Array.from(first)).toEqual(Array.from(second));
}, 30_000);

test("a different password gives a different master key", async () => {
  const a = await deriveMasterKey(PASSWORD, EMAIL);
  const b = await deriveMasterKey(PASSWORD + "!", EMAIL);
  expect(Array.from(a)).not.toEqual(Array.from(b));
}, 30_000);

test("the same password under a different email gives a different master key", async () => {
  const a = await deriveMasterKey(PASSWORD, "a@example.se");
  const b = await deriveMasterKey(PASSWORD, "b@example.se");
  expect(Array.from(a)).not.toEqual(Array.from(b));
}, 30_000);

test("the login hash satisfies the Cognito password policy", async () => {
  // The pool requires 12+ characters with upper, lower, digit and symbol. The
  // fixed prefix guarantees all four regardless of what base64 produces.
  const hash = await deriveLoginHash(await deriveMasterKey(PASSWORD, EMAIL));
  expect(hash.startsWith(LOGIN_HASH_PREFIX)).toBe(true);
  expect(hash.length).toBeGreaterThanOrEqual(12);
  expect(hash).toMatch(/[A-Z]/);
  expect(hash).toMatch(/[a-z]/);
  expect(hash).toMatch(/[0-9]/);
  expect(hash).toMatch(/[^A-Za-z0-9]/);
}, 30_000);

test("the login hash and the KEK are different keys from one master key", async () => {
  // If these collided, the value sent to Cognito would also open the vault.
  const master = await deriveMasterKey(PASSWORD, EMAIL);
  const hash = await deriveLoginHash(master);
  const kek = await deriveUserKek(master);
  const kekB64 = btoa(String.fromCharCode(...kek));
  expect(hash).not.toContain(kekB64);
  expect(kek.length).toBe(32);
}, 30_000);

test("the KEK is not the master key itself", async () => {
  const master = await deriveMasterKey(PASSWORD, EMAIL);
  const kek = await deriveUserKek(master);
  expect(Array.from(kek)).not.toEqual(Array.from(master));
}, 30_000);

test("a recovery key derives from a code and differs per code", async () => {
  const a = await deriveRecoveryKey("KM7QF2X9-HB3RNT8W-VE65YJQD-P4ZC9NKR");
  const b = await deriveRecoveryKey("KM7QF2X9-HB3RNT8W-VE65YJQD-P4ZC9NKS");
  expect(a.length).toBe(32);
  expect(Array.from(a)).not.toEqual(Array.from(b));
});

test("NFC and NFD spellings of a password containing \u00f6 derive the same master key", async () => {
  // Composed with \\u escapes, not literal characters, so the test file's own
  // source encoding cannot make the two forms accidentally identical: NFC is
  // one precomposed codepoint (U+00F6), NFD is "o" followed by a combining
  // diaeresis (U+0308).
  const nfc = "l\u00f6senord";
  const nfd = "lo\u0308senord";
  expect(nfc).not.toBe(nfd);
  expect(nfd.normalize("NFC")).toBe(nfc);

  const a = await deriveMasterKey(nfc, EMAIL);
  const b = await deriveMasterKey(nfd, EMAIL);
  expect(Array.from(a)).toEqual(Array.from(b));
}, 30_000);

test("NFC and NFD spellings of an email containing \u00f6 derive the same salt", async () => {
  const nfc = "anna.l\u00f6f@example.se";
  const nfd = "anna.lo\u0308f@example.se";
  expect(nfc).not.toBe(nfd);
  expect(nfd.normalize("NFC")).toBe(nfc);

  const a = await deriveSalt(nfc);
  const b = await deriveSalt(nfd);
  expect(Array.from(a)).toEqual(Array.from(b));
});

test("an ASCII password is unaffected by NFC normalisation", async () => {
  const a = await deriveMasterKey(PASSWORD, EMAIL);
  const b = await deriveMasterKey(PASSWORD.normalize("NFC"), EMAIL);
  expect(PASSWORD).toBe(PASSWORD.normalize("NFC"));
  expect(Array.from(a)).toEqual(Array.from(b));
}, 30_000);

test("the argon parameters are the ones the spec pins", () => {
  expect(ARGON2ID.timeCost).toBe(3);
  expect(ARGON2ID.memoryKiB).toBe(65536);
  expect(ARGON2ID.parallelism).toBe(1);
  expect(ARGON2ID.hashLength).toBe(32);
  expect(HKDF_INFO.login).toBe("datavalv/login/v1");
  expect(HKDF_INFO.kek).toBe("datavalv/kek/v1");
  expect(HKDF_INFO.recovery).toBe("datavalv/recovery/v1");
});
