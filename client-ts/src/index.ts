/**
 * Datavalv's TypeScript client: the four calls, the single-use token and the
 * `datavalv` command, for a server that runs Node.
 *
 * The format itself lives in `@datavalv/crypto`, which the browser application
 * uses too — one implementation of the bytes, used by both ends, checked
 * against the Python client by the conformance matrix.
 */

export { DatavalvClient } from "./client.js";
export type {
  CreatedBackup,
  CreatedVault,
  DatavalvClientOptions,
  PushedBackup,
  TenantPublicKey,
} from "./client.js";
export {
  DEFAULT_TIMEOUT_MS,
  DEFAULT_UPLOAD_TIMEOUT_MS,
  MAX_LABEL_LENGTH,
  MAX_NAME_CIPHER_B64,
} from "./client.js";
export {
  ApiError,
  AuthError,
  ConfigurationError,
  DatavalvError,
  NetworkError,
  QuotaExceeded,
  RequestInFlight,
  StorageFull,
  UploadError,
  VaultKeyChanged,
  VaultNotInitialized,
} from "./errors.js";
export { FilePins, KNOWN_VAULTS_ENV, MemoryPins } from "./pins.js";
export type { KeyPins, PinScope } from "./pins.js";
export { generateSigningKeypair, writePrivateKey } from "./keys.js";
export type { SigningKeypair } from "./keys.js";

/**
 * Kept in step with `version` in package.json by `tests/packaging.test.ts`.
 * Two hand-maintained numbers drift apart quietly, and the one a user ends up
 * with is the one in the tarball's manifest.
 */
export const VERSION = "0.7.0";
