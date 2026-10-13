import { beforeAll, expect, test } from "vitest";
import { HEADER_LENGTH, IV_LENGTH, TAG_LENGTH } from "../src/formatConstants.js";
import {
  decrypt,
  decryptWithTenantKey,
  encrypt,
  encryptToTenantKey,
  generateDek,
  generateKeypair,
  publicKeyFromPrivateKey,
  unwrapDek,
  wrapDek,
} from "../src/crypto.js";
import { b64decode } from "../src/pem.js";

const PLAINTEXT = new TextEncoder().encode("a club's backup archive".repeat(100));

let keys: { publicKeyPem: string; privateKeyPem: string };
beforeAll(async () => {
  keys = await generateKeypair();
}, 30_000);

test("dek is 256 bits", async () => {
  expect((await generateDek()).length).toBe(32);
});

test("round trip recovers the plaintext", async () => {
  const dek = await generateDek();
  const out = await decrypt(await encrypt(PLAINTEXT, dek), dek);
  expect(Array.from(out)).toEqual(Array.from(PLAINTEXT));
});

test("ciphertext length is plaintext plus header and tag", async () => {
  const dek = await generateDek();
  const blob = await encrypt(PLAINTEXT, dek);
  expect(blob.length).toBe(HEADER_LENGTH + PLAINTEXT.length + TAG_LENGTH);
});

test("encrypting twice produces different ciphertext", async () => {
  const dek = await generateDek();
  const a = await encrypt(PLAINTEXT, dek);
  const b = await encrypt(PLAINTEXT, dek);
  expect(Array.from(a)).not.toEqual(Array.from(b));
});

test("explicit iv is used verbatim", async () => {
  const iv = new Uint8Array(Array.from({ length: IV_LENGTH }, (_, i) => i));
  const blob = await encrypt(PLAINTEXT, await generateDek(), iv);
  expect(Array.from(blob.slice(9, HEADER_LENGTH))).toEqual(Array.from(iv));
});

test("wrong key fails to decrypt", async () => {
  const blob = await encrypt(PLAINTEXT, await generateDek());
  await expect(decrypt(blob, await generateDek())).rejects.toThrow();
});

test("tampering with the iv in the header is detected", async () => {
  const dek = await generateDek();
  const blob = await encrypt(PLAINTEXT, dek);
  blob[9] = blob[9]! ^ 0xff;
  await expect(decrypt(blob, dek)).rejects.toThrow();
});

test("tampering with the body is detected", async () => {
  const dek = await generateDek();
  const blob = await encrypt(PLAINTEXT, dek);
  blob[HEADER_LENGTH] = blob[HEADER_LENGTH]! ^ 0x01;
  await expect(decrypt(blob, dek)).rejects.toThrow();
});

test("unknown version is rejected before decryption", async () => {
  const dek = await generateDek();
  const blob = await encrypt(PLAINTEXT, dek);
  blob[4] = 2;
  await expect(decrypt(blob, dek)).rejects.toThrow(/version/);
});

test("dek wrap round trip", async () => {
  const dek = await generateDek();
  const wrapped = await wrapDek(dek, keys.publicKeyPem);
  expect(Array.from(await unwrapDek(wrapped, keys.privateKeyPem))).toEqual(Array.from(dek));
});

test("wrapping is randomised", async () => {
  const dek = await generateDek();
  const a = await wrapDek(dek, keys.publicKeyPem);
  const b = await wrapDek(dek, keys.publicKeyPem);
  expect(Array.from(a)).not.toEqual(Array.from(b));
});

// --- short strings encrypted straight to a tenant key ---------------------
//
// Addresses, in practice: the half of the at-rest design that has to be shown
// to a member rather than compared, so it is encrypted rather than digested.
//
// Non-ASCII written as escapes and never typed. An editor recomposes what you
// type on save, at which point DECOMPOSED_EMAIL becomes the same string as
// EMAIL and the round trip below compares a string to itself.
const EMAIL = "m\u00e5ns@brommas\u00e5.se";
const DECOMPOSED_EMAIL = "ma\u030ans@brommasa\u030a.se";

test("the two spellings are two different strings", () => {
  // Guards the round trip below rather than the implementation: recomposed,
  // the decomposed case is a duplicate that tests nothing new.
  expect(EMAIL).not.toBe(DECOMPOSED_EMAIL);
});

test.each([EMAIL, DECOMPOSED_EMAIL, "\u4e2d\u6587@example.cn", "a@b.se"])(
  "tenant key text round trip %s",
  async (text) => {
    const cipherB64 = await encryptToTenantKey(text, keys.publicKeyPem);
    expect(await decryptWithTenantKey(cipherB64, keys.privateKeyPem)).toBe(text);
  },
);

test("the ciphertext does not contain the address", async () => {
  // A primitive that returned its input unchanged would satisfy the round trip
  // above; this is the assertion that would not let it.
  const cipherB64 = await encryptToTenantKey(EMAIL, keys.publicKeyPem);
  expect(cipherB64).not.toContain(EMAIL);
  expect(new TextDecoder().decode(b64decode(cipherB64))).not.toContain(EMAIL);
});

test("encrypting one address twice gives different ciphertext", async () => {
  // OAEP is randomised, and that is why it is the right vehicle here: two rows
  // carrying one address must not be equal by inspection, or the operator can
  // tell which members share an address without holding any key.
  const first = await encryptToTenantKey(EMAIL, keys.publicKeyPem);
  const second = await encryptToTenantKey(EMAIL, keys.publicKeyPem);
  expect(first).not.toBe(second);
  expect(await decryptWithTenantKey(first, keys.privateKeyPem)).toBe(
    await decryptWithTenantKey(second, keys.privateKeyPem),
  );
});

test("a wrong tenant key fails rather than returning nonsense", async () => {
  // The failure has to be loud. An address that came back as rubbish would be
  // rendered as rubbish in a member list rather than reported.
  const other = await generateKeypair();
  const cipherB64 = await encryptToTenantKey(EMAIL, keys.publicKeyPem);
  await expect(decryptWithTenantKey(cipherB64, other.privateKeyPem)).rejects.toThrow();
}, 30_000);

test("it does not normalise what it is given", async () => {
  // Deliberately not normaliseEmail's job. This is the spelling a member will
  // be shown, so lowercasing it here would display an address nobody typed.
  const typed = "M\u00e5ns@Brommass.SE";
  const cipherB64 = await encryptToTenantKey(typed, keys.publicKeyPem);
  expect(await decryptWithTenantKey(cipherB64, keys.privateKeyPem)).toBe(typed);
});

test("the public half derived from a private key is the one it was generated with", async () => {
  // The whole correctness of the derivation, and the only assertion that can
  // catch it producing a *valid but different* key: a browser that encrypted an
  // address to such a key would write a member row nothing can ever open, and
  // every round trip below would still pass because it would be using the same
  // wrong key for both halves.
  expect(await publicKeyFromPrivateKey(keys.privateKeyPem)).toBe(keys.publicKeyPem);
});

test("an address encrypted to the derived half opens with the private key", async () => {
  // What the inviter's and the invitee's browsers actually do: they hold the
  // tenant private key, derive the half that encrypts, and write a ciphertext
  // the member list opens later with the key they started from.
  const derived = await publicKeyFromPrivateKey(keys.privateKeyPem);
  const cipherB64 = await encryptToTenantKey(EMAIL, derived);
  expect(await decryptWithTenantKey(cipherB64, keys.privateKeyPem)).toBe(EMAIL);
});

test("deriving carries nothing private into the public key", async () => {
  // A PEM that still said PRIVATE KEY, or that carried d/p/q along in its DER,
  // would be a tenant private key published to the server as a public one. The
  // banner is the cheap half; the length is the half that would catch a key
  // that merely renamed itself, since an RSA-3072 SPKI is a few hundred bytes
  // and a PKCS#8 of the same key is several times that.
  const derived = await publicKeyFromPrivateKey(keys.privateKeyPem);
  expect(derived).toContain("-----BEGIN PUBLIC KEY-----");
  expect(derived).not.toContain("PRIVATE");
  expect(derived.length).toBeLessThan(keys.privateKeyPem.length / 2);
});

test("a key that is not a private key is refused rather than derived from", async () => {
  await expect(publicKeyFromPrivateKey(keys.publicKeyPem)).rejects.toThrow();
});
