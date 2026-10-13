/**
 * Datavalv v1 content encryption in the browser.
 *
 * AES-256-GCM with the 21-byte header as additional authenticated data, and
 * RSA-OAEP/SHA-256 with an EMPTY label for wrapping the data key.
 *
 * The label is empty on purpose: RsaOaepParams.label has had uneven support
 * across browser engines, and ciphertext one engine can read and another cannot
 * means permanently unreadable backups. Domain separation is structural - DEKs
 * are wrapped with a tenant key, tenant keys with a member key.
 */

import {
  AES_KEY_BITS,
  HEADER_LENGTH,
  IV_LENGTH,
  RSA_HASH,
  RSA_MODULUS_BITS,
} from "./formatConstants.js";
import { decodeHeader, encodeHeader } from "./format.js";
import { b64decode, b64encode, derToPem, pemToDer } from "./pem.js";

const subtle = () => globalThis.crypto.subtle;
const encoder = new TextEncoder();
const decoder = new TextDecoder();

/**
 * Bytes backed by a plain ArrayBuffer.
 *
 * Since TypeScript 5.7 `Uint8Array` is generic over `ArrayBufferLike`, which
 * includes `SharedArrayBuffer` and is therefore not assignable to WebCrypto's
 * `BufferSource`. Pinning the buffer type keeps the calls type-safe without
 * casts or defensive copies.
 */
export type Bytes = Uint8Array<ArrayBuffer>;

const RSA_PARAMS: RsaHashedKeyGenParams = {
  name: "RSA-OAEP",
  modulusLength: RSA_MODULUS_BITS,
  publicExponent: new Uint8Array([1, 0, 1]),
  hash: RSA_HASH,
};

export async function generateDek(): Promise<Bytes> {
  return globalThis.crypto.getRandomValues(new Uint8Array(AES_KEY_BITS / 8));
}

/**
 * SHA-256 of a byte string, lowercase hex.
 *
 * Used to check a downloaded ciphertext against the digest the source
 * application registered. That digest is of the CIPHERTEXT, not the plaintext:
 * the uploader hashes the sealed blob, S3 verifies it against the signed
 * checksum header on PUT, and `complete` re-verifies it with HeadObject. So it
 * is a fact about the stored object that three parties already agreed on.
 */
export async function sha256Hex(bytes: Bytes): Promise<string> {
  const digest = await subtle().digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export async function encrypt(
  plaintext: Bytes,
  dek: Bytes,
  iv?: Bytes,
): Promise<Bytes> {
  const nonce = iv ?? globalThis.crypto.getRandomValues(new Uint8Array(IV_LENGTH));
  const header = encodeHeader(nonce);
  const key = await subtle().importKey("raw", dek, "AES-GCM", false, ["encrypt"]);
  const sealed = await subtle().encrypt(
    { name: "AES-GCM", iv: nonce, additionalData: header, tagLength: 128 },
    key,
    plaintext,
  );
  const out = new Uint8Array(header.length + sealed.byteLength);
  out.set(header, 0);
  out.set(new Uint8Array(sealed), header.length);
  return out;
}

export async function decrypt(blob: Bytes, dek: Bytes): Promise<Bytes> {
  const iv = decodeHeader(blob);
  const header = blob.slice(0, HEADER_LENGTH);
  const key = await subtle().importKey("raw", dek, "AES-GCM", false, ["decrypt"]);
  const opened = await subtle().decrypt(
    { name: "AES-GCM", iv, additionalData: header, tagLength: 128 },
    key,
    blob.slice(HEADER_LENGTH),
  );
  return new Uint8Array(opened);
}

/**
 * The OAEP arguments, written once.
 *
 * Every RSA operation in this package goes through the two functions below. A
 * second `{ name: "RSA-OAEP", hash: ... }` spelled out beside them is two
 * things that can drift, and the drift is undetectable until a ciphertext one
 * half produced is one the other half cannot open — at which point the data is
 * already stored. `label` is left off `RSA_OAEP_PARAMS` deliberately: absent is
 * the empty label, and that is the parameter this file's header is about.
 */
const RSA_OAEP_IMPORT: RsaHashedImportParams = { name: "RSA-OAEP", hash: RSA_HASH };
const RSA_OAEP_PARAMS: RsaOaepParams = { name: "RSA-OAEP" };

/** RSA-OAEP/SHA-256, empty label, to a public key. */
export async function rsaOaepEncrypt(data: Bytes, publicKeyPem: string): Promise<Bytes> {
  const key = await subtle().importKey("spki", pemToDer(publicKeyPem), RSA_OAEP_IMPORT, false, [
    "encrypt",
  ]);
  return new Uint8Array(await subtle().encrypt(RSA_OAEP_PARAMS, key, data));
}

/** RSA-OAEP/SHA-256, empty label, with a private key. Rejects on the wrong key. */
export async function rsaOaepDecrypt(data: Bytes, privateKeyPem: string): Promise<Bytes> {
  const key = await subtle().importKey("pkcs8", pemToDer(privateKeyPem), RSA_OAEP_IMPORT, false, [
    "decrypt",
  ]);
  return new Uint8Array(await subtle().decrypt(RSA_OAEP_PARAMS, key, data));
}

export async function wrapDek(dek: Bytes, publicKeyPem: string): Promise<Bytes> {
  return rsaOaepEncrypt(dek, publicKeyPem);
}

export async function unwrapDek(wrapped: Bytes, privateKeyPem: string): Promise<Bytes> {
  return rsaOaepDecrypt(wrapped, privateKeyPem);
}

/**
 * Encrypt a short string straight to a tenant's public key. Base64 out.
 *
 * For the values that have to be *shown* to a member rather than compared —
 * email addresses, today. They ride under the tenant key directly rather than
 * under a DEK the way a filename does, because a filename has a backup to
 * belong to and an address has none.
 *
 * Randomised, because OAEP is. Two rows carrying one address must not be equal
 * by inspection; testing equality is the server's keyed HMAC's job, and the
 * browser is never given that key.
 *
 * Does **not** normalise. What goes in comes back out code point for code
 * point, because this is the spelling a member will be shown. `normaliseEmail`
 * is for the digest that gets compared, and conflating the two would mean
 * displaying a lowercased address the member never typed.
 *
 * RSA-3072-OAEP/SHA-256 takes at most 318 bytes; WebCrypto rejects anything
 * longer rather than truncating.
 */
export async function encryptToTenantKey(text: string, publicKeyPem: string): Promise<string> {
  return b64encode(await rsaOaepEncrypt(encoder.encode(text) as Bytes, publicKeyPem));
}

/** The other half of {@link encryptToTenantKey}. Rejects on the wrong key. */
export async function decryptWithTenantKey(
  cipherB64: string,
  privateKeyPem: string,
): Promise<string> {
  return decoder.decode(await rsaOaepDecrypt(b64decode(cipherB64), privateKeyPem));
}

/**
 * The public half of an RSA private key, as a PEM.
 *
 * **Why this exists at all:** encrypting to the tenant key is a public-key
 * operation, and the two browsers that have to perform one hold the *private*
 * key and nothing else. The inviter unwrapped it out of their own `MEMBER#`
 * row; the invitee unwrapped it out of the invitation, with the secret from the
 * link's fragment. Neither was ever sent the tenant's public key, and neither
 * needs to be: an RSA public key is (n, e), both of which are part of the
 * private key, so the half that encrypts is derivable from the half that
 * decrypts and the server is not involved in supplying it.
 *
 * Deliberately not a second way to *make* a key. Nothing random happens here;
 * `publicKeyFromPrivateKey(pair.privateKeyPem)` is `pair.publicKeyPem`, which
 * is what `crypto.test.ts` pins — because the failure this could otherwise have
 * is an address encrypted to a key that is not the tenant's, which type-checks
 * perfectly and is only discovered when a member list will not open.
 *
 * The JWK round trip is the only route WebCrypto offers: there is no
 * "export the public half of this private key". Stripping the private fields
 * by naming the two public ones rather than by deleting the rest is
 * deliberate — a future JWK field this code has not heard of cannot ride along
 * into something that is about to be published.
 */
export async function publicKeyFromPrivateKey(privateKeyPem: string): Promise<string> {
  const priv = await subtle().importKey(
    "pkcs8",
    pemToDer(privateKeyPem),
    RSA_OAEP_IMPORT,
    // Extractable, unavoidably: the JWK export below is the derivation. The
    // key came in as a PEM the caller already holds in the clear, so this
    // grants nothing that was not already granted.
    true,
    ["decrypt"],
  );
  const { kty, n, e } = await subtle().exportKey("jwk", priv);
  const pub = await subtle().importKey(
    "jwk",
    { kty, n, e, alg: "RSA-OAEP-256", ext: true },
    RSA_OAEP_IMPORT,
    true,
    ["encrypt"],
  );
  const spki = new Uint8Array(await subtle().exportKey("spki", pub));
  return derToPem(spki, "PUBLIC KEY");
}

export async function generateKeypair(): Promise<{ publicKeyPem: string; privateKeyPem: string }> {
  const pair = await subtle().generateKey(RSA_PARAMS, true, ["encrypt", "decrypt"]);
  const spki = new Uint8Array(await subtle().exportKey("spki", pair.publicKey));
  const pkcs8 = new Uint8Array(await subtle().exportKey("pkcs8", pair.privateKey));
  return {
    publicKeyPem: derToPem(spki, "PUBLIC KEY"),
    privateKeyPem: derToPem(pkcs8, "PRIVATE KEY"),
  };
}

/**
 * The fingerprint of a public key: SHA-256 over its SubjectPublicKeyInfo DER,
 * as 64 lowercase hex characters.
 *
 * **This exists because the server hands out public keys and is the one party
 * that must not be trusted about them.** A source application encrypts every
 * backup's data key to the tenant public key it fetched from
 * `GET /v1/tenants/{externalId}/public-key`; a server that answered with a key
 * of its own would read every backup from then on. No signature from the
 * server can help, because the server is the adversary. What can is two people
 * comparing one short string outside the service: a member reads the
 * fingerprint of the key their browser derived from the tenant *private* key
 * it holds, and whoever runs the source application reads the fingerprint of
 * the key their server was given.
 *
 * So the definition is chosen to be computable by anybody, with nothing of
 * ours installed:
 *
 *     openssl pkey -pubin -outform DER | openssl dgst -sha256
 *
 * Over the DER, never the PEM text: line endings and wrapping differ between
 * tools that agree about the key. Through WebCrypto rather than over
 * `pemToDer`'s bytes directly, for two reasons -- importing proves the input
 * *is* an RSA public key, so a private key or a truncated paste is refused
 * instead of being given a fingerprint nothing else will ever match (which
 * would read as "the key was substituted", the one alarm this must not raise
 * falsely); and the re-export is the canonical encoding whatever came in.
 */
export async function publicKeyFingerprint(publicKeyPem: string): Promise<string> {
  const key = await subtle().importKey(
    "spki",
    pemToDer(publicKeyPem.trim()),
    RSA_OAEP_IMPORT,
    true,
    ["encrypt"],
  );
  return sha256Hex(new Uint8Array(await subtle().exportKey("spki", key)));
}
