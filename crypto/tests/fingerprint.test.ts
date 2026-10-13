import { readFileSync } from "node:fs";
import { expect, test } from "vitest";
import { generateKeypair, publicKeyFingerprint, publicKeyFromPrivateKey } from "../src/index.js";

/**
 * The fingerprint is how two people check, outside this service, that the key a
 * source application encrypts to is the key the vault's members hold. So the
 * one property that matters is that everybody computes the same string -- this
 * code, a client library in another language, and a person with `openssl`.
 *
 * The expected value below was produced by none of this project's code. It is
 * `publicKeyPem` from `format/vectors/v1/vectors.json`, through:
 *
 *   openssl pkey -pubin -outform DER | openssl dgst -sha256
 */
const VECTORS = JSON.parse(
  readFileSync(new URL("../../format/vectors/v1/vectors.json", import.meta.url), "utf8"),
) as { publicKeyPem: string; privateKeyPem: string };
const OPENSSL_SAYS = "de6272b8151979389437054b06df8a817a6ad62ab87faac4bbacb3360c1385d0";

test("agrees with openssl about the vector keypair", async () => {
  expect(await publicKeyFingerprint(VECTORS.publicKeyPem)).toBe(OPENSSL_SAYS);
});

test("is the same whether the public key was stored or derived from the private one", async () => {
  // A member's browser holds the vault's *private* key and derives the public
  // half from it; a source application is handed the public half by the API.
  // The comparison only means anything if both routes end at one string.
  const derived = await publicKeyFromPrivateKey(VECTORS.privateKeyPem);
  expect(await publicKeyFingerprint(derived)).toBe(OPENSSL_SAYS);
});

test("is a property of the key, not of how its PEM happens to be laid out", async () => {
  // CRLF line endings, a body on one line, trailing whitespace: the same key,
  // so the same fingerprint. A fingerprint over the PEM *text* would differ for
  // each, and two honest parties would be told their keys do not match.
  const publicKeyPem = VECTORS.publicKeyPem;
  const body = publicKeyPem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");
  const relaid = [
    publicKeyPem.replace(/\n/g, "\r\n"),
    `-----BEGIN PUBLIC KEY-----\n${body}\n-----END PUBLIC KEY-----`,
    `  ${publicKeyPem}  \n\n`,
  ];
  for (const pem of relaid) {
    expect(await publicKeyFingerprint(pem)).toBe(OPENSSL_SAYS);
  }
});

test("differs between two keys", async () => {
  const other = await generateKeypair();
  const fingerprint = await publicKeyFingerprint(other.publicKeyPem);
  expect(fingerprint).toMatch(/^[0-9a-f]{64}$/);
  expect(fingerprint).not.toBe(OPENSSL_SAYS);
}, 60_000);

test("refuses a private key rather than fingerprinting the wrong thing", async () => {
  // Both are PEM strings and both would hash. A fingerprint of the private
  // key's bytes matches nothing anybody else can compute, which reads as "the
  // key was substituted" -- the one alarm this must not raise falsely.
  await expect(publicKeyFingerprint(VECTORS.privateKeyPem)).rejects.toThrow();
});
