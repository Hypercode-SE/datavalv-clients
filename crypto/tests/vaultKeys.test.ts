import { beforeAll, expect, test } from "vitest";
import { generateKeypair } from "../src/crypto.js";
import { deriveRecoveryKey, deriveUserKek, deriveMasterKey } from "../src/derive.js";
import {
  unwrapPrivateKeyWithKek,
  unwrapPrivateKeyWithPrivateKey,
  wrapPrivateKeyWithKek,
  wrapPrivateKeyWithPublicKey,
} from "../src/vaultKeys.js";

let member: { publicKeyPem: string; privateKeyPem: string };
let tenant: { publicKeyPem: string; privateKeyPem: string };

beforeAll(async () => {
  member = await generateKeypair();
  tenant = await generateKeypair();
}, 60_000);

test("a private key round-trips through a KEK", async () => {
  const kek = await deriveUserKek(await deriveMasterKey("pw", "a@example.se"));
  const wrapped = await wrapPrivateKeyWithKek(member.privateKeyPem, kek);
  expect(wrapped).not.toContain("PRIVATE KEY");
  expect(await unwrapPrivateKeyWithKek(wrapped, kek)).toBe(member.privateKeyPem);
}, 30_000);

test("the wrong KEK cannot unwrap", async () => {
  const right = await deriveUserKek(await deriveMasterKey("pw", "a@example.se"));
  const wrong = await deriveUserKek(await deriveMasterKey("other", "a@example.se"));
  const wrapped = await wrapPrivateKeyWithKek(member.privateKeyPem, right);
  await expect(unwrapPrivateKeyWithKek(wrapped, wrong)).rejects.toThrow();
}, 60_000);

test("wrapping twice gives different ciphertext", async () => {
  const kek = await deriveUserKek(await deriveMasterKey("pw", "a@example.se"));
  const a = await wrapPrivateKeyWithKek(member.privateKeyPem, kek);
  const b = await wrapPrivateKeyWithKek(member.privateKeyPem, kek);
  expect(a).not.toBe(b);
}, 30_000);

test("the same private key can be wrapped under a password KEK and a recovery key", async () => {
  // This is what makes the recovery code a real second path rather than an
  // escrow: two independent wrappings of one key.
  const kek = await deriveUserKek(await deriveMasterKey("pw", "a@example.se"));
  const recovery = await deriveRecoveryKey("KM7QF2X9-HB3RNT8W-VE65YJQD-P4ZC9NKR");

  const byPassword = await wrapPrivateKeyWithKek(member.privateKeyPem, kek);
  const byRecovery = await wrapPrivateKeyWithKek(member.privateKeyPem, recovery);

  expect(await unwrapPrivateKeyWithKek(byPassword, kek)).toBe(member.privateKeyPem);
  expect(await unwrapPrivateKeyWithKek(byRecovery, recovery)).toBe(member.privateKeyPem);
  await expect(unwrapPrivateKeyWithKek(byRecovery, kek)).rejects.toThrow();
}, 60_000);

test("a tenant key round-trips through a member keypair", async () => {
  const wrapped = await wrapPrivateKeyWithPublicKey(tenant.privateKeyPem, member.publicKeyPem);
  expect(await unwrapPrivateKeyWithPrivateKey(wrapped, member.privateKeyPem)).toBe(
    tenant.privateKeyPem,
  );
}, 30_000);

test("another member's private key cannot unwrap the tenant key", async () => {
  const outsider = await generateKeypair();
  const wrapped = await wrapPrivateKeyWithPublicKey(tenant.privateKeyPem, member.publicKeyPem);
  await expect(
    unwrapPrivateKeyWithPrivateKey(wrapped, outsider.privateKeyPem),
  ).rejects.toThrow();
}, 60_000);
