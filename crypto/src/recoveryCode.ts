/**
 * Recovery codes.
 *
 * 160 bits, rendered as Crockford base32 in four groups of eight. Crockford
 * rather than RFC 4648 because this code is read off paper and typed back
 * months later: it drops I, L, O and U, and decoding accepts the substitutions
 * a human actually makes (O for 0, I or L for 1).
 *
 * Losing this code together with the password means the vault cannot be opened
 * by anyone, so every affordance here is in service of it being transcribed
 * correctly.
 */

import type { Bytes } from "./crypto.js";

export const CROCKFORD_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

const CODE_BYTES = 20; // 160 bits
const CODE_CHARS = 32; // 160 / 5
const GROUP = 8;

function decodeChar(character: string): number {
  const upper = character.toUpperCase();
  // Crockford's documented forgiving substitutions.
  if (upper === "O") return 0;
  if (upper === "I" || upper === "L") return 1;
  const index = CROCKFORD_ALPHABET.indexOf(upper);
  if (index < 0) throw new Error(`invalid character in recovery code: ${character}`);
  return index;
}

export function formatRecoveryCode(bytes: Bytes): string {
  let bits = 0;
  let value = 0;
  let out = "";
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += CROCKFORD_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += CROCKFORD_ALPHABET[(value << (5 - bits)) & 31];

  const groups: string[] = [];
  for (let i = 0; i < out.length; i += GROUP) groups.push(out.slice(i, i + GROUP));
  return groups.join("-");
}

export function recoveryCodeToBytes(code: string): Bytes {
  const cleaned = code.replace(/[\s-]/g, "");
  if (cleaned.length !== CODE_CHARS) {
    throw new Error(`a recovery code is 32 characters, got ${cleaned.length}`);
  }

  const out = new Uint8Array(CODE_BYTES) as Bytes;
  let bits = 0;
  let value = 0;
  let written = 0;
  for (const character of cleaned) {
    value = (value << 5) | decodeChar(character);
    bits += 5;
    if (bits >= 8) {
      out[written++] = (value >>> (bits - 8)) & 0xff;
      bits -= 8;
    }
  }
  return out;
}

export function generateRecoveryCode(): string {
  const bytes = globalThis.crypto.getRandomValues(new Uint8Array(CODE_BYTES)) as Bytes;
  return formatRecoveryCode(bytes);
}
