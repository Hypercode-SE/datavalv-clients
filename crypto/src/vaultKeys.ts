/**
 * Wrapping and unwrapping of private keys.
 *
 * Two shapes, for the two places a private key is stored:
 *
 *   - under a symmetric KEK (AES-256-GCM), for a member's own private key held
 *     server-side. It is wrapped twice — once under the password-derived KEK and
 *     once under the recovery key — which is what makes the recovery code a
 *     genuine second path rather than an escrow.
 *   - under a public key (RSA-OAEP), for the tenant private key stored once per
 *     member.
 *
 * An RSA-3072 private key in PKCS#8 is larger than RSA-OAEP can encrypt
 * directly, so the public-key path wraps a fresh AES key and encrypts the PEM
 * under that.
 *
 * The RSA half goes through `crypto.ts`'s `rsaOaepEncrypt`/`rsaOaepDecrypt`
 * rather than spelling the OAEP arguments out again. This file used to carry
 * its own copy of them, which is the drift `format/` exists to prevent: a hash
 * or a label that disagreed with the one `wrapDek` uses would make a tenant key
 * wrapped by one path unopenable by the other, and nothing would fail until a
 * member tried to accept an invitation.
 */

import type { Bytes } from "./crypto.js";
import { rsaOaepDecrypt, rsaOaepEncrypt } from "./crypto.js";
import { IV_LENGTH } from "./formatConstants.js";
import { b64decode, b64encode } from "./pem.js";

const subtle = () => globalThis.crypto.subtle;
const encoder = new TextEncoder();
const decoder = new TextDecoder();

function randomIv(): Bytes {
  return globalThis.crypto.getRandomValues(new Uint8Array(IV_LENGTH)) as Bytes;
}

export async function wrapPrivateKeyWithKek(privateKeyPem: string, kek: Bytes): Promise<string> {
  const iv = randomIv();
  const key = await subtle().importKey("raw", kek, "AES-GCM", false, ["encrypt"]);
  const sealed = await subtle().encrypt(
    { name: "AES-GCM", iv, tagLength: 128 },
    key,
    encoder.encode(privateKeyPem),
  );
  const out = new Uint8Array(iv.length + sealed.byteLength) as Bytes;
  out.set(iv, 0);
  out.set(new Uint8Array(sealed), iv.length);
  return b64encode(out);
}

export async function unwrapPrivateKeyWithKek(wrappedB64: string, kek: Bytes): Promise<string> {
  const blob = b64decode(wrappedB64);
  const iv = blob.slice(0, IV_LENGTH);
  const key = await subtle().importKey("raw", kek, "AES-GCM", false, ["decrypt"]);
  const opened = await subtle().decrypt(
    { name: "AES-GCM", iv, tagLength: 128 },
    key,
    blob.slice(IV_LENGTH),
  );
  return decoder.decode(opened);
}

/**
 * Wraps a private key under a public key.
 *
 * RSA-OAEP cannot encrypt a PKCS#8 RSA-3072 private key directly — the
 * plaintext is larger than the modulus allows — so this wraps a fresh AES key
 * with RSA and encrypts the PEM under that AES key.
 *
 * Returns a JSON envelope, not base64: `{k: base64 RSA-wrapped AES key, b:
 * base64 IV‖ciphertext of the PEM}`.
 */
export async function wrapPrivateKeyWithPublicKey(
  privateKeyPem: string,
  publicKeyPem: string,
): Promise<string> {
  const sessionKey = globalThis.crypto.getRandomValues(new Uint8Array(32)) as Bytes;
  const body = await wrapPrivateKeyWithKek(privateKeyPem, sessionKey);
  const wrappedSessionKey = await rsaOaepEncrypt(sessionKey, publicKeyPem);
  return JSON.stringify({ k: b64encode(wrappedSessionKey), b: body });
}

export async function unwrapPrivateKeyWithPrivateKey(
  wrapped: string,
  privateKeyPem: string,
): Promise<string> {
  const { k, b } = JSON.parse(wrapped) as { k: string; b: string };
  const sessionKey = await rsaOaepDecrypt(b64decode(k), privateKeyPem);
  return unwrapPrivateKeyWithKek(b, sessionKey);
}
