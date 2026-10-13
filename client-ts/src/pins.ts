/**
 * Which key each vault was first seen with, so that a different one is refused.
 *
 * **The service hands out the key every backup is encrypted to, and the service
 * is the one party this design does not trust with plaintext.** Step 1 of a
 * push is `GET /v1/tenants/{externalId}/public-key`. A server that answered it
 * with a key of its own would read every backup pushed from then on, and
 * nothing in the protocol could show it: no signature from the server helps
 * when the server is the adversary, and `keyId` is the server's own value.
 *
 * What does help is memory. A vault's key is made once, in its first member's
 * browser, and never changes, so the first key this machine is given for a
 * vault is either the vault's or an attack that was already under way -- and
 * every later one has to be the same. This module is that memory, in the shape
 * of SSH's `known_hosts`: trust on first use, written down, and a refusal
 * afterwards.
 *
 * **First use is the part a person closes.** The fingerprint
 * (`publicKeyFingerprint` in `@datavalv/crypto`) is defined so that `openssl`
 * computes it, and the vault's owner is shown theirs under their backups,
 * worked out in their browser from the private key they hold. Compared once,
 * the pin stops being "whatever we were first told" and becomes "the vault's
 * key".
 *
 * The file is JSON, one entry per vault, and is the same file the Python
 * client writes -- one machine may run either client, or both:
 *
 *     {"version": 1,
 *      "vaults": {"<api base> <client id> <external id>": {"fingerprint": "<64 hex>"}}}
 *
 * The scope is all three, because `kund-4711` on staging and on production are
 * different vaults, and so is another application's `kund-4711`.
 */
import {
  closeSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  rmSync,
  writeSync,
} from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { randomBytes } from "node:crypto";

import { ConfigurationError } from "./errors.js";

/** Where `FilePins.default()` keeps its file unless this says otherwise. */
export const KNOWN_VAULTS_ENV = "DATAVALV_KNOWN_VAULTS";
const VERSION = 1;

export type PinScope = readonly [apiBase: string, clientId: string, externalId: string];

function scopeOf(apiBase: string, clientId: string, externalId: string): string {
  return `${apiBase} ${clientId} ${externalId}`;
}

/** Somewhere a fingerprint can be remembered between pushes. */
export interface KeyPins {
  get(apiBase: string, clientId: string, externalId: string): string | undefined;
  set(apiBase: string, clientId: string, externalId: string, fingerprint: string): void;
}

/**
 * Pins that live as long as this object.
 *
 * Two uses. A long-running process that keeps its own state and hands the same
 * `MemoryPins` to every client it builds. And a machine with no disk to
 * remember on -- a container that starts empty every night sees every key for
 * the first time, which is no protection at all -- whose operator compares the
 * fingerprint once and passes it in from configuration:
 *
 *     new MemoryPins([[[apiBase, clientId, "kund-4711"], "de6272b8..."]])
 *
 * A vault whose key is not that one is then refused from the first push.
 */
export class MemoryPins implements KeyPins {
  readonly #pins = new Map<string, string>();

  constructor(known: Iterable<readonly [PinScope, string]> = []) {
    for (const [scope, fingerprint] of known) this.#pins.set(scopeOf(...scope), fingerprint);
  }

  get(apiBase: string, clientId: string, externalId: string): string | undefined {
    return this.#pins.get(scopeOf(apiBase, clientId, externalId));
  }

  set(apiBase: string, clientId: string, externalId: string, fingerprint: string): void {
    this.#pins.set(scopeOf(apiBase, clientId, externalId), fingerprint);
  }

  forget(apiBase: string, clientId: string, externalId: string): void {
    this.#pins.delete(scopeOf(apiBase, clientId, externalId));
  }
}

type Vaults = Record<string, { fingerprint: string }>;

/**
 * Pins in a JSON file that only its owner can read.
 *
 * Read on every `get` and rewritten whole on every `set`, through a temporary
 * file and a rename, so a push that is killed mid-write leaves the old file and
 * not half of a new one. Two pushes that pin two *different* vaults in the same
 * instant can lose one entry to the other's rename; the loser is pinned again
 * on its next push, which is a second first-use and nothing worse.
 *
 * **A file that cannot be read as a pin file stops the push.** Treating a
 * corrupt or unreadable file as an empty one would turn "somebody damaged the
 * pin file" into "every key is new, carry on" -- the attack with one extra
 * step.
 */
export class FilePins implements KeyPins {
  readonly path: string;

  constructor(path: string) {
    this.path = path.startsWith("~/") ? join(homedir(), path.slice(2)) : path;
  }

  /** `$DATAVALV_KNOWN_VAULTS`, else the user's state directory. */
  static default(): FilePins {
    const explicit = (process.env[KNOWN_VAULTS_ENV] ?? "").trim();
    if (explicit) return new FilePins(explicit);
    const state = (process.env["XDG_STATE_HOME"] ?? "").trim() || join(homedir(), ".local", "state");
    return new FilePins(join(state, "datavalv", "known_vaults.json"));
  }

  #read(): Vaults {
    let text: string;
    try {
      text = readFileSync(this.path, "utf8");
    } catch (exc) {
      if ((exc as NodeJS.ErrnoException).code === "ENOENT") return {};
      throw new ConfigurationError(
        `cannot read the known-vaults file at ${this.path}: ${(exc as Error).message}. ` +
          `Set ${KNOWN_VAULTS_ENV} to a path this user can read and write.`,
      );
    }
    try {
      const document = JSON.parse(text) as { version?: unknown; vaults?: unknown };
      const vaults = document.vaults;
      if (document.version !== VERSION || typeof vaults !== "object" || vaults === null || Array.isArray(vaults)) {
        throw new Error("not a version 1 known-vaults file");
      }
      return vaults as Vaults;
    } catch (exc) {
      throw new ConfigurationError(
        `${this.path} is not a known-vaults file (${(exc as Error).message}). It is not ` +
          "treated as empty: that would accept any key for every vault. Look at why it " +
          "changed, then restore or remove it.",
      );
    }
  }

  #write(vaults: Vaults): void {
    const directory = dirname(this.path);
    const temporary = join(directory, `.known_vaults.${randomBytes(6).toString("hex")}`);
    try {
      mkdirSync(directory, { recursive: true, mode: 0o700 });
      // Created at 0600, exclusively: the entries are never readable by anybody
      // else, not even for the moment before a chmod.
      const fd = openSync(temporary, "wx", 0o600);
      try {
        writeSync(fd, `${JSON.stringify({ version: VERSION, vaults }, null, 1)}\n`);
      } finally {
        closeSync(fd);
      }
      renameSync(temporary, this.path);
    } catch (exc) {
      rmSync(temporary, { force: true });
      throw new ConfigurationError(
        `cannot write the known-vaults file at ${this.path}: ${(exc as Error).message}. ` +
          "This client remembers each vault's key so that a changed one is refused. " +
          `Set ${KNOWN_VAULTS_ENV} to a writable path, or pass \`pins\`.`,
      );
    }
  }

  get(apiBase: string, clientId: string, externalId: string): string | undefined {
    const entry = this.#read()[scopeOf(apiBase, clientId, externalId)];
    return typeof entry === "object" && entry !== null ? entry.fingerprint : undefined;
  }

  set(apiBase: string, clientId: string, externalId: string, fingerprint: string): void {
    const vaults = this.#read();
    vaults[scopeOf(apiBase, clientId, externalId)] = { fingerprint };
    this.#write(vaults);
  }

  forget(apiBase: string, clientId: string, externalId: string): void {
    const vaults = this.#read();
    const scope = scopeOf(apiBase, clientId, externalId);
    if (scope in vaults) {
      delete vaults[scope];
      this.#write(vaults);
    }
  }
}
