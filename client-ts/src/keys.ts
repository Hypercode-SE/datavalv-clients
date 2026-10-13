/**
 * The source application's signing keypair, and the one careful thing about
 * writing the private half down.
 *
 * `node:crypto` rather than `@datavalv/crypto`: this key signs JWTs, it is not
 * part of the backup format, and WebCrypto cannot generate an
 * `RSASSA-PKCS1-v1_5` key and hand it out as a PKCS#8 PEM without a detour
 * through export and re-import. `generateKeyPairSync` produces exactly the two
 * PEMs `/applications` and `jose` expect — the same SPKI/PKCS#8 encodings the
 * Python client's `crypto.generate_keypair` produces, which is what lets a key
 * made by one client be used by the other.
 */

// The DEFAULT export, not `node:fs/promises`. An ES module namespace object is
// immutable, and `tests/cli.test.ts` has to be able to replace `chmod` with a
// no-op to prove that the mode on `open` — not a chmod afterwards — is what
// creates the key unreadable. `fs.promises` is an ordinary object, so it can.
import fs from "node:fs";
import { generateKeyPairSync } from "node:crypto";

import { RSA_MODULUS_BITS } from "@datavalv/crypto";

export interface SigningKeypair {
  privateKeyPem: string;
  publicKeyPem: string;
}

/** RSA-3072, the modulus size `format/v1.json` pins for this project. */
export function generateSigningKeypair(): SigningKeypair {
  const { privateKey, publicKey } = generateKeyPairSync("rsa", {
    modulusLength: RSA_MODULUS_BITS,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  return { privateKeyPem: privateKey, publicKeyPem: publicKey };
}

/**
 * Write the private half to a file that has never existed readable.
 *
 * The mode goes to `open`, which applies it as the file is created. Writing it
 * world-readable and chmodding it a moment later would pass every test that
 * looks at the finished file, and that moment is the whole vulnerability:
 * anything watching the directory wins the race and has the key.
 *
 * `force` unlinks rather than truncates, so the descriptor below is created
 * fresh at 0600. Truncating an existing file keeps whatever mode that file
 * already had, which may be the mode that made replacing the key necessary.
 */
export async function writePrivateKey(
  path: string,
  pem: string,
  options: { force?: boolean } = {},
): Promise<void> {
  if (options.force) {
    await fs.promises.rm(path, { force: true });
  }

  // "wx" is O_WRONLY | O_CREAT | O_EXCL: it fails rather than following a
  // symlink an attacker planted, and it never opens a file that already exists.
  const handle = await fs.promises.open(path, "wx", 0o600);
  try {
    await handle.writeFile(pem, "utf8");
  } finally {
    await handle.close();
  }

  // Explicit, because the mode passed to `open` is masked by the umask and a
  // umask that clears the owner's write bit would leave a key file its owner
  // cannot rotate. This sets exactly 0600 — it can give the owner their own
  // write bit back, and it grants nothing to group or other under any umask.
  //
  // It is a tidy-up, not the protection: the file was created at 0600 above, so
  // there is no moment at which it exists readable. Deleting this line leaves
  // the key safe; passing 0o644 to `open` does not, which is what
  // `tests/cli.test.ts`'s permissive-umask test holds apart by neutering this
  // call.
  await fs.promises.chmod(path, 0o600);
}
