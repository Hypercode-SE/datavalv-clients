import { readFileSync } from "node:fs";
import { expect, test } from "@playwright/test";

type Case = {
  name: string;
  plaintextB64: string;
  dekB64: string;
  ivB64: string;
  ciphertextB64: string;
  wrappedDekB64: string;
};

const vectors = JSON.parse(
  readFileSync(new URL("../../../format/vectors/v1/vectors.json", import.meta.url), "utf8"),
) as { privateKeyPem: string; cases: Case[] };

/**
 * WebCrypto's `subtle` is only exposed in a secure context, so `about:blank`
 * leaves `crypto.subtle` undefined. Intercept a https origin and serve an empty
 * document from it: no server to run, and the page is a secure context.
 */
const ORIGIN = "https://vectors.datavalv.test/";

async function openSecurePage(page: import("@playwright/test").Page): Promise<void> {
  await page.route(`${ORIGIN}**`, (route) =>
    route.fulfill({ contentType: "text/html", body: "<!doctype html><title>vectors</title>" }),
  );
  await page.goto(ORIGIN);
}

test("golden vectors decrypt identically in this engine", async ({ page }) => {
  await openSecurePage(page);

  for (const c of vectors.cases) {
    const result = await page.evaluate(
      async ([ciphertextB64, dekB64]) => {
        const b64d = (t: string) => Uint8Array.from(atob(t), (ch) => ch.charCodeAt(0));
        const b64e = (b: Uint8Array) => {
          let s = "";
          for (const x of b) s += String.fromCharCode(x);
          return btoa(s);
        };
        const blob = b64d(ciphertextB64);
        const header = blob.slice(0, 21);
        const iv = blob.slice(9, 21);
        const key = await crypto.subtle.importKey("raw", b64d(dekB64), "AES-GCM", false, [
          "decrypt",
        ]);
        const opened = await crypto.subtle.decrypt(
          { name: "AES-GCM", iv, additionalData: header, tagLength: 128 },
          key,
          blob.slice(21),
        );
        return b64e(new Uint8Array(opened));
      },
      [c.ciphertextB64, c.dekB64] as const,
    );
    expect(result, `vector ${c.name}`).toBe(c.plaintextB64);
  }
});

test("rsa-oaep unwrapping behaves identically in this engine", async ({ page }) => {
  await openSecurePage(page);
  const c = vectors.cases[1]!;

  const result = await page.evaluate(
    async ([wrappedB64, privateKeyPem]) => {
      const b64d = (t: string) => Uint8Array.from(atob(t), (ch) => ch.charCodeAt(0));
      const b64e = (b: Uint8Array) => {
        let s = "";
        for (const x of b) s += String.fromCharCode(x);
        return btoa(s);
      };
      const der = b64d(privateKeyPem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, ""));
      const key = await crypto.subtle.importKey(
        "pkcs8",
        der,
        { name: "RSA-OAEP", hash: "SHA-256" },
        false,
        ["decrypt"],
      );
      const dek = await crypto.subtle.decrypt({ name: "RSA-OAEP" }, key, b64d(wrappedB64));
      return b64e(new Uint8Array(dek));
    },
    [c.wrappedDekB64, vectors.privateKeyPem] as const,
  );

  expect(result).toBe(c.dekB64);
});
