import { readFileSync } from "node:fs";
import { expect, test } from "vitest";
import { decrypt, encrypt, unwrapDek } from "../src/crypto.js";
import { b64decode, b64encode } from "../src/pem.js";

type Case = {
  name: string;
  plaintextB64: string;
  dekB64: string;
  ivB64: string;
  ciphertextB64: string;
  wrappedDekB64: string;
};

const vectors = JSON.parse(
  readFileSync(new URL("../../format/vectors/v1/vectors.json", import.meta.url), "utf8"),
) as { publicKeyPem: string; privateKeyPem: string; cases: Case[] };

test.each(vectors.cases.map((c) => [c.name, c] as const))(
  "%s: produces the vector ciphertext byte for byte",
  async (_name, c) => {
    const produced = await encrypt(b64decode(c.plaintextB64), b64decode(c.dekB64), b64decode(c.ivB64));
    expect(b64encode(produced)).toBe(c.ciphertextB64);
  },
);

test.each(vectors.cases.map((c) => [c.name, c] as const))(
  "%s: decrypts the vector ciphertext",
  async (_name, c) => {
    const out = await decrypt(b64decode(c.ciphertextB64), b64decode(c.dekB64));
    expect(b64encode(out)).toBe(c.plaintextB64);
  },
);

test.each(vectors.cases.map((c) => [c.name, c] as const))(
  "%s: unwraps the vector dek",
  async (_name, c) => {
    const dek = await unwrapDek(b64decode(c.wrappedDekB64), vectors.privateKeyPem);
    expect(b64encode(dek)).toBe(c.dekB64);
  },
);
