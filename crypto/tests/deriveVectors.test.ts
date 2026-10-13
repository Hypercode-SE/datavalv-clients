import { expect, test } from "vitest";
import { deriveLoginHash, deriveMasterKey, deriveRecoveryKey, deriveSalt, deriveUserKek } from "../src/derive.js";
import { b64encode } from "../src/pem.js";

/**
 * Known-answer vectors for key derivation.
 *
 * The expected values below were produced once by running the current,
 * correct implementation (fixed Argon2id/HKDF parameters, fixed info
 * strings) against the fixed inputs and pasting the outputs in as literals.
 * `derive.test.ts` proves properties (reproducible, sensitive to input,
 * differs per field) but never proves that `deriveMasterKey` actually
 * consumed `ARGON2ID.memoryKiB` rather than some other number — a test
 * asserting `ARGON2ID.memoryKiB === 65536` stays green even if the
 * derivation call itself hardcodes a different value. These vectors close
 * that gap: any change to a pinned constant or to an info string changes the
 * output and fails the comparison below.
 *
 * If a test in this file fails, either a constant drifted (e.g.
 * `ARGON2ID.memoryKiB`) or the derivation logic changed. In both cases every
 * existing account's login hash and KEK would be invalidated by the change
 * that caused the failure — accounts derived under the old parameters could
 * no longer authenticate or decrypt their vault with the same password. The
 * fix is therefore never to regenerate this file's literals to match new
 * output. Investigate why the derivation changed, and if the change is
 * intentional, it needs an explicit migration for existing accounts, not a
 * quiet update to a test vector.
 */

const EMAIL = "vector.user@example.se";
const PASSWORD = "known-answer-vector-password-1";
const RECOVERY_CODE = "KM7QF2X9-HB3RNT8W-VE65YJQD-P4ZC9NKR";

const EXPECTED_SALT_B64 = "zTUuD7cUJyu6ZSyWlkQp/+VtF3Uqu10C6c7P6c3ALQs=";
const EXPECTED_MASTER_KEY_B64 = "NV/t6bn3P1F8BRIZ8RmkBWQZOOjknaIC758Lq/0me6M=";
const EXPECTED_LOGIN_HASH = "Dv1!F8msle1J7THZFOruYdhLGCDP9mpLUIbxT7XaVSHVfXI=";
const EXPECTED_KEK_B64 = "iTbgqYrvA7WckxAlnKkzrG8G+1NpiQXD8keyNRf8xQ8=";
const EXPECTED_RECOVERY_KEY_B64 = "bso8SMaHlJX+rm0r04XCj2X5NOgbZHT/IM6h2nxiqOE=";

test("known-answer vector: deriveSalt", async () => {
  const salt = await deriveSalt(EMAIL);
  expect(b64encode(salt)).toBe(EXPECTED_SALT_B64);
});

test("known-answer vector: deriveMasterKey", async () => {
  const master = await deriveMasterKey(PASSWORD, EMAIL);
  expect(b64encode(master)).toBe(EXPECTED_MASTER_KEY_B64);
}, 30_000);

test("known-answer vector: deriveLoginHash", async () => {
  const master = await deriveMasterKey(PASSWORD, EMAIL);
  const loginHash = await deriveLoginHash(master);
  expect(loginHash).toBe(EXPECTED_LOGIN_HASH);
}, 30_000);

test("known-answer vector: deriveUserKek", async () => {
  const master = await deriveMasterKey(PASSWORD, EMAIL);
  const kek = await deriveUserKek(master);
  expect(b64encode(kek)).toBe(EXPECTED_KEK_B64);
}, 30_000);

test("known-answer vector: deriveRecoveryKey", async () => {
  const recoveryKey = await deriveRecoveryKey(RECOVERY_CODE);
  expect(b64encode(recoveryKey)).toBe(EXPECTED_RECOVERY_KEY_B64);
});
