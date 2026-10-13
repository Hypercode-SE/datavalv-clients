/**
 * Key derivation.
 *
 * One password produces two independent values: a login hash that goes to
 * Cognito, and a key-encryption key that never leaves the browser. Both come
 * from one Argon2id master key via HKDF with different info strings, so
 * learning the value Cognito stores tells an attacker nothing about the KEK.
 *
 * Argon2id is memory-hard and deliberately slow — about a second at these
 * parameters. That cost is the whole point: it is what makes a stolen password
 * database expensive to attack. The UI must explain the wait rather than hide
 * it.
 */

import { argon2id } from "hash-wasm";

import type { Bytes } from "./crypto.js";
import { ARGON2ID, HKDF_INFO, LOGIN_HASH_PREFIX } from "./formatConstants.js";
import { recoveryCodeToBytes } from "./recoveryCode.js";

const subtle = () => globalThis.crypto.subtle;
const encoder = new TextEncoder();

export function normaliseEmail(email: string): string {
  // NFC before lowercasing: å/ä/ö typed on an NFD-emitting input path (macOS
  // filesystem-adjacent paths, some IMEs) must salt identically to the same
  // email typed as precomposed NFC, or the salt — and everything derived from
  // it — silently diverges per platform.
  return email.trim().normalize("NFC").toLowerCase();
}

export async function deriveSalt(email: string): Promise<Bytes> {
  // Deterministic from the email, so there is no "fetch my salt" endpoint to
  // enumerate accounts with.
  const material = encoder.encode(ARGON2ID.saltPrefix + normaliseEmail(email));
  const digest = await subtle().digest("SHA-256", material);
  return new Uint8Array(digest) as Bytes;
}

export async function deriveMasterKey(password: string, email: string): Promise<Bytes> {
  const salt = await deriveSalt(email);
  // NFC before UTF-8 encoding: an NFD-composed password (å = "a" + combining
  // ring above) must derive the same master key as its NFC spelling, or a
  // Swedish password typed on a platform that emits NFD locks the user out of
  // their own vault with no diagnosis available and no recovery but the
  // recovery code. NFC is the W3C's recommended normalisation form for the
  // web and is idempotent, so ASCII passwords are unaffected.
  const normalisedPassword = password.normalize("NFC");
  const hex = await argon2id({
    password: normalisedPassword,
    salt,
    parallelism: ARGON2ID.parallelism,
    iterations: ARGON2ID.timeCost,
    memorySize: ARGON2ID.memoryKiB,
    hashLength: ARGON2ID.hashLength,
    outputType: "binary",
  });
  return new Uint8Array(hex) as Bytes;
}

/**
 * HKDF-SHA256 with an empty salt.
 *
 * Exported so that every derivation in this package goes through one
 * implementation. A second HKDF written beside this one is exactly the
 * divergence `format/` exists to prevent: it would take a different info
 * string, or a different salt, and nothing would fail until a key derived by
 * one half could not open what the other half wrapped.
 *
 * `ikm` is either the Argon2id master key or another value that is already
 * full-entropy CSPRNG output (a recovery code, an invite secret). It is never
 * a password: HKDF is fast by design and offers no brute-force resistance.
 */
export async function hkdf(ikm: Bytes, info: string, lengthBytes = 32): Promise<Bytes> {
  const key = await subtle().importKey("raw", ikm, "HKDF", false, ["deriveBits"]);
  const bits = await subtle().deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      // An empty salt is correct here: the input keying material is already
      // either the output of a salted, memory-hard KDF or full-entropy random
      // bytes, and the info string provides the separation.
      salt: new Uint8Array(0),
      info: encoder.encode(info),
    },
    key,
    lengthBytes * 8,
  );
  return new Uint8Array(bits) as Bytes;
}

export async function deriveLoginHash(masterKey: Bytes): Promise<string> {
  const bytes = await hkdf(masterKey, HKDF_INFO.login);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  // The prefix guarantees the Cognito password policy is satisfied whatever
  // base64 happens to produce.
  return LOGIN_HASH_PREFIX + btoa(binary);
}

export async function deriveUserKek(masterKey: Bytes): Promise<Bytes> {
  return hkdf(masterKey, HKDF_INFO.kek);
}

export async function deriveRecoveryKey(code: string): Promise<Bytes> {
  // The code is already 160 bits of CSPRNG output, so a fast KDF is right here
  // — there is nothing to brute-force that a slow one would protect.
  return hkdf(recoveryCodeToBytes(code), HKDF_INFO.recovery);
}
