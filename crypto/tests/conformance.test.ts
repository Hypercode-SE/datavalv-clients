import { execFileSync } from "node:child_process";
import { expect, test } from "vitest";
import { generateKeypair } from "../src/crypto.js";
import { b64encode } from "../src/pem.js";

const PLAINTEXT = new TextEncoder().encode("conformance payload");
const DEK = new Uint8Array(Array.from({ length: 32 }, (_, i) => i));
const IV = new Uint8Array(Array.from({ length: 12 }, (_, i) => i));

function run(mode: "encrypt" | "decrypt", job: unknown): Record<string, string> {
  const out = execFileSync("npx", ["tsx", "src/conformance.ts", mode], {
    input: JSON.stringify(job),
    encoding: "utf8",
  });
  return JSON.parse(out);
}

test("encrypt then decrypt through the cli", async () => {
  const keys = await generateKeypair();
  const enc = run("encrypt", {
    plaintextB64: b64encode(PLAINTEXT),
    dekB64: b64encode(DEK),
    ivB64: b64encode(IV),
    publicKeyPem: keys.publicKeyPem,
  });
  const dec = run("decrypt", {
    ciphertextB64: enc.ciphertextB64,
    wrappedDekB64: enc.wrappedDekB64,
    privateKeyPem: keys.privateKeyPem,
  });
  expect(dec.plaintextB64).toBe(b64encode(PLAINTEXT));
}, 60_000);

test("rejected ciphertext reports an error without crashing", async () => {
  const keys = await generateKeypair();
  const enc = run("encrypt", {
    plaintextB64: b64encode(PLAINTEXT),
    dekB64: b64encode(DEK),
    ivB64: b64encode(IV),
    publicKeyPem: keys.publicKeyPem,
  });
  const bytes = Uint8Array.from(atob(enc.ciphertextB64!), (c) => c.charCodeAt(0));
  bytes[4] = 2;
  const dec = run("decrypt", {
    ciphertextB64: b64encode(bytes),
    wrappedDekB64: enc.wrappedDekB64,
    privateKeyPem: keys.privateKeyPem,
  });
  expect(dec.error).toMatch(/version/);
  expect(dec.plaintextB64).toBeUndefined();
}, 60_000);
