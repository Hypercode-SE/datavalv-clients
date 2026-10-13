/** PEM to DER conversion. WebCrypto imports raw DER; the API exchanges PEM. */

import type { Bytes } from "./crypto.js";

export function b64encode(bytes: Bytes): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

export function b64decode(text: string): Bytes {
  const binary = atob(text);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

export function derToPem(der: Bytes, label: "PUBLIC KEY" | "PRIVATE KEY"): string {
  const body = b64encode(der).match(/.{1,64}/g) ?? [];
  return `-----BEGIN ${label}-----\n${body.join("\n")}\n-----END ${label}-----\n`;
}

export function pemToDer(pem: string): Bytes {
  const body = pem
    .replace(/-----BEGIN [^-]+-----/, "")
    .replace(/-----END [^-]+-----/, "")
    .replace(/\s+/g, "");
  return b64decode(body);
}
