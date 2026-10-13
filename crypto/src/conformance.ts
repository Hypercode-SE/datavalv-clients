/**
 * Conformance CLI: one JSON job on stdin, one JSON result on stdout.
 *
 * Contract is identical to python -m datavalv_client.conformance, so CI can
 * pipe between the two implementations and prove they agree on live code.
 *
 * A rejected ciphertext is a RESULT, reported as {"error": ...} with exit 0.
 * Exit code 2 means the job itself was malformed.
 */

import {
  decrypt,
  decryptWithTenantKey,
  encrypt,
  encryptToTenantKey,
  unwrapDek,
  wrapDek,
} from "./crypto.js";
import { deriveInviteKey } from "./invite.js";
import { b64decode, b64encode } from "./pem.js";

const MODES = ["encrypt", "decrypt", "invite-key", "encrypt-text", "decrypt-text"] as const;
type Mode = (typeof MODES)[number];

async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) chunks.push(chunk as Buffer);
  return Buffer.concat(chunks).toString("utf8");
}

async function doEncrypt(job: Record<string, string>): Promise<Record<string, string>> {
  const dek = b64decode(job.dekB64!);
  const blob = await encrypt(b64decode(job.plaintextB64!), dek, b64decode(job.ivB64!));
  const wrapped = await wrapDek(dek, job.publicKeyPem!);
  return { ciphertextB64: b64encode(blob), wrappedDekB64: b64encode(wrapped) };
}

async function doDecrypt(job: Record<string, string>): Promise<Record<string, string>> {
  try {
    const dek = await unwrapDek(b64decode(job.wrappedDekB64!), job.privateKeyPem!);
    const plaintext = await decrypt(b64decode(job.ciphertextB64!), dek);
    return { plaintextB64: b64encode(plaintext) };
  } catch (exc) {
    const name = exc instanceof Error ? exc.name : "Error";
    const message = exc instanceof Error ? exc.message : String(exc);
    return { error: `${name}: ${message}` };
  }
}

/**
 * A short string encrypted straight to a tenant key — an address, in practice.
 *
 * Text in and text out rather than base64 in and base64 out: the defect this
 * crossing exists to catch is a UTF-8 one, and comparing base64 would let a
 * mangled code point through as long as both sides mangled it the same way.
 */
async function doEncryptText(job: Record<string, string>): Promise<Record<string, string>> {
  return { cipherB64: await encryptToTenantKey(job.text!, job.publicKeyPem!) };
}

async function doDecryptText(job: Record<string, string>): Promise<Record<string, string>> {
  try {
    return { text: await decryptWithTenantKey(job.cipherB64!, job.privateKeyPem!) };
  } catch (exc) {
    const name = exc instanceof Error ? exc.name : "Error";
    const message = exc instanceof Error ? exc.message : String(exc);
    return { error: `${name}: ${message}` };
  }
}

/** Hex in, hex out: the invite vectors are hex, and stay hex end to end. */
function fromHex(hex: string): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i += 1) out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out as Uint8Array<ArrayBuffer>;
}

async function doInviteKey(job: Record<string, string>): Promise<Record<string, string>> {
  const key = await deriveInviteKey(fromHex(job.secretHex!));
  return {
    inviteKeyHex: Array.from(key, (b) => b.toString(16).padStart(2, "0")).join(""),
  };
}

async function main(): Promise<number> {
  const mode = process.argv[2] as Mode;
  if (!MODES.includes(mode)) {
    process.stderr.write(`usage: conformance ${MODES.join("|")}\n`);
    return 2;
  }
  let job: Record<string, string>;
  try {
    job = JSON.parse(await readStdin());
  } catch (exc) {
    process.stderr.write(`malformed job: ${String(exc)}\n`);
    return 2;
  }
  const handlers = {
    encrypt: doEncrypt,
    decrypt: doDecrypt,
    "invite-key": doInviteKey,
    "encrypt-text": doEncryptText,
    "decrypt-text": doDecryptText,
  };
  const result = await handlers[mode](job);
  process.stdout.write(JSON.stringify(result));
  return 0;
}

// Set exitCode rather than calling process.exit(): process.exit() does not wait
// for pending stdout writes to flush when stdout is a pipe, so a result larger
// than the 64 KB pipe buffer is silently truncated mid-JSON. Letting Node exit
// on its own drains stdout first.
main().then((code) => {
  process.exitCode = code;
});
