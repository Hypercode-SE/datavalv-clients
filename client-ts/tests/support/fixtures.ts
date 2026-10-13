/**
 * The two keypairs every suite needs, generated once per test file.
 *
 * RSA-3072 costs real time, and the same pair being reused across the tests in
 * one file is exactly the arrangement the Python suite gets from its
 * session-scoped fixtures.
 */

import { generateSigningKeypair, type SigningKeypair } from "../../src/keys.js";

/** The source application's key. RSA-3072, as `datavalv keygen` makes. */
export const signingKey: SigningKeypair = generateSigningKeypair();

/** The vault's key. In production this is made in a member's browser. */
export const tenantKey: SigningKeypair = generateSigningKeypair();
