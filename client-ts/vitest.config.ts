import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    include: ["tests/**/*.test.ts"],
    // Points the default pin file at a temporary directory before every test.
    setupFiles: ["tests/support/pinsInTmp.ts"],
    // RSA-3072 keygen, a real HTTP server and two Python subprocesses live in
    // `interop.test.ts`. The default 5 s is comfortable for the rest and not
    // for that one.
    testTimeout: 120_000,
    hookTimeout: 120_000,
  },
});
