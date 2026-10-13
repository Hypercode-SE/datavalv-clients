import { expect, test } from "vitest";

test("WebCrypto is available in the test environment", () => {
  expect(globalThis.crypto?.subtle).toBeDefined();
});
