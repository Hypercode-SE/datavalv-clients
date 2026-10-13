/** The public surface of the Datavalv crypto package. */

// The frozen v1 constants, generated from `format/v1.json` by
// `scripts/gen_constants.py`. Re-exported rather than left as a deep import,
// because `exports` in package.json admits this module and nothing else: a
// consumer that needs the modulus size or the header length must be able to
// read it from the one place the format is defined, or it will write the number
// down a second time and the two will drift.
export {
  AES_KEY_BITS,
  ALG_ID,
  ARGON2ID,
  HEADER_LENGTH,
  HKDF_INFO,
  IV_LENGTH,
  LOGIN_HASH_PREFIX,
  MAGIC,
  RSA_HASH,
  RSA_MODULUS_BITS,
  TAG_LENGTH,
  VERSION,
} from "./formatConstants.js";
export {
  decrypt,
  decryptWithTenantKey,
  encrypt,
  encryptToTenantKey,
  generateDek,
  generateKeypair,
  publicKeyFingerprint,
  publicKeyFromPrivateKey,
  rsaOaepDecrypt,
  rsaOaepEncrypt,
  sha256Hex,
  unwrapDek,
  wrapDek,
} from "./crypto.js";
export type { Bytes } from "./crypto.js";
export { FormatError, decodeHeader, encodeHeader } from "./format.js";
export { b64decode, b64encode, derToPem, pemToDer } from "./pem.js";
export {
  deriveLoginHash,
  deriveMasterKey,
  deriveRecoveryKey,
  deriveSalt,
  deriveUserKek,
  normaliseEmail,
} from "./derive.js";
export { deriveInviteKey } from "./invite.js";
export {
  CROCKFORD_ALPHABET,
  formatRecoveryCode,
  generateRecoveryCode,
  recoveryCodeToBytes,
} from "./recoveryCode.js";
export {
  unwrapPrivateKeyWithKek,
  unwrapPrivateKeyWithPrivateKey,
  wrapPrivateKeyWithKek,
  wrapPrivateKeyWithPublicKey,
} from "./vaultKeys.js";
