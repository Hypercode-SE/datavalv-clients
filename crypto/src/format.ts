/**
 * Datavalv ciphertext header encoding and decoding.
 *
 * Pure byte manipulation, no cryptography. Error messages deliberately share
 * keywords with the Python implementation so the conformance tamper matrix can
 * assert both sides reject for the same reason.
 */

import { ALG_ID, HEADER_LENGTH, IV_LENGTH, MAGIC, VERSION } from "./formatConstants.js";
import type { Bytes } from "./crypto.js";

export class FormatError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "FormatError";
  }
}

export function encodeHeader(iv: Bytes): Bytes {
  if (iv.length !== IV_LENGTH) {
    throw new FormatError(`iv length must be ${IV_LENGTH}, got ${iv.length}`);
  }
  const header = new Uint8Array(HEADER_LENGTH);
  header.set(MAGIC, 0);
  header[4] = VERSION;
  header[5] = ALG_ID;
  header[6] = 0;
  header[7] = 0;
  header[8] = IV_LENGTH;
  header.set(iv, 9);
  return header;
}

export function decodeHeader(blob: Bytes): Bytes {
  if (blob.length < HEADER_LENGTH) {
    throw new FormatError(`truncated header: need ${HEADER_LENGTH} bytes, got ${blob.length}`);
  }
  for (let i = 0; i < MAGIC.length; i++) {
    if (blob[i] !== MAGIC[i]) {
      throw new FormatError("bad magic: not a Datavalv ciphertext");
    }
  }
  if (blob[4] !== VERSION) throw new FormatError(`unsupported version ${blob[4]}`);
  if (blob[5] !== ALG_ID) throw new FormatError(`unsupported algorithm ${blob[5]}`);
  if (blob[6] !== 0 || blob[7] !== 0) throw new FormatError("reserved bytes must be zero");
  if (blob[8] !== IV_LENGTH) throw new FormatError(`iv length must be ${IV_LENGTH}, got ${blob[8]}`);
  return blob.slice(9, HEADER_LENGTH);
}
