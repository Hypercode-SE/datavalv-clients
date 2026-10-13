/**
 * `datavalv` — the operator's side of connecting a server, as three commands.
 *
 * The same three commands, the same flags and the same exit codes as the Python
 * client's `datavalv`. Somebody who has run one should be able to run the other
 * from memory; where the two differ at all it is a bug in one of them.
 *
 * What `/connect-system` asks of an operator is a keypair made with `openssl`, a
 * registration in the browser, a JWT minted per call because a token is single
 * use, and four HTTP calls in one order with an `x-amz-checksum-sha256` header
 * on the third. Two of those are genuinely irreducible: the keypair has to be
 * made on the machine that will sign with it, and the registration has to be
 * done by a signed-in person. The rest is this:
 *
 *     datavalv keygen                        # a keypair; the public half to paste
 *     datavalv vault create --external-id …  # one vault, for one customer
 *     datavalv push dump.sql.gz --external-id …
 *
 * **Registration is not here and will not be.** `POST /v1/apps` sits on the
 * Cognito authorizer, so it needs a signed-in account — and a command-line tool
 * that asked for a Datavalv password would be asking for the one password this
 * product is built never to see. `keygen` prints the public half; a person
 * pastes it into `/applications` and gets back the two ids.
 *
 * Settings come from flags, falling back to the environment:
 *
 *     DATAVALV_API          https://api.datavalv.se
 *     DATAVALV_CLIENT_ID    what /applications issued
 *     DATAVALV_KEY_ID       the kid of the registered signing key
 *     DATAVALV_PRIVATE_KEY  a PATH to the key file — never the key itself
 *
 * That last one is a path on purpose. A private key in an environment variable
 * is in `ps`, in the shell history of whatever set it, and in every crash dump
 * of the process that read it.
 *
 * Identifiers go to stdout and everything else to stderr, so
 * `BACKUP=$(datavalv push …)` holds a backup id and nothing else.
 */

import fs from "node:fs";
import path from "node:path";
import { parseArgs } from "node:util";

import { publicKeyFingerprint } from "@datavalv/crypto";

import { DatavalvClient } from "./client.js";
import { VERSION } from "./index.js";
import {
  ApiError,
  AuthError,
  ConfigurationError,
  DatavalvError,
  VaultKeyChanged,
} from "./errors.js";
import { generateSigningKeypair, writePrivateKey } from "./keys.js";
import { FilePins } from "./pins.js";

/**
 * Exit codes, for a schedule that branches on them.
 *
 * `EXIT_RETRY` is the one that earns its keep: a vault whose owner has not
 * signed in yet answers `409 tenant_not_initialized`, and a cron job that treats
 * that as a failure pages somebody about a server that is working perfectly.
 * Anything under `RETRY` is worth running again unchanged; anything under
 * `REFUSED` or `CONFIG` needs a person.
 *
 * The numbers are the Python client's, value for value. A shop running both
 * must be able to write one rule in one scheduler.
 */
export const EXIT_OK = 0;
export const EXIT_FAILED = 1;
export const EXIT_USAGE = 2;
export const EXIT_CONFIG = 3;
export const EXIT_AUTH = 4;
export const EXIT_RETRY = 5;
export const EXIT_REFUSED = 6;
/**
 * Neither of its neighbours. 5 would have a schedule push again every night
 * against a key that is wrong every night; 6 says the *service* refused, when
 * this is the client refusing the service. It needs a person, and it needs them
 * to know which thing to go and compare.
 */
export const EXIT_KEY_CHANGED = 7;

export const DEFAULT_KEY_FILENAME = "datavalv-signing.pem";

export const EXIT_TABLE = `exit codes:
  0  done
  1  failed for a reason not covered below
  2  the command line was wrong
  3  a setting, or a file named on the command line, is missing or unusable
  4  the signing key, client id or key id was refused
  5  nothing is wrong; run it again later (vault not started yet, network, quota)
  6  the service refused the request and a person must look at it
  7  the key offered for the vault is not the one on record; nothing was sent`;

const CONNECTION_HELP = `connection settings (a flag wins over the variable):
  --api ADDRESS             API address [$DATAVALV_API]
  --client-id ID            registered client id [$DATAVALV_CLIENT_ID]
  --key-id ID               registered signing key id [$DATAVALV_KEY_ID]
  --private-key PATH        path to the signing key PEM [$DATAVALV_PRIVATE_KEY]`;

/**
 * The four steps, in the one order they work in.
 *
 * A list of commands says what each one does and nothing about which comes
 * first, and three of these are done once ever while the fourth runs nightly.
 * Step 2 is not a command at all — nothing here can register a key, because
 * registering it is an act of the account that owns the server — and leaving
 * it out is what makes step 3 fail with 403 for a reader who thought `keygen`
 * had done it.
 */
const ORDER = `getting started, in order:
  1. datavalv keygen                 make the signing keypair; the private
                                     half never leaves this machine
  2. paste the public half into      registering it is what lets the service
     /applications, in the browser   check a signature; no command does this
  3. datavalv vault create           one vault per customer, once each
  4. datavalv push FILE              nightly, from cron or your own scheduler

  Steps 1-3 happen once. Only step 4 repeats.`;

export const USAGE = `usage: datavalv [-h] {keygen,vault,push} ...

Push end-to-end encrypted backups to Datavalv.

Every copy is encrypted on this machine, against a public key belonging to
the customer's vault, before anything leaves. What reaches the service is
ciphertext, a size, a digest and a label: nobody there can read a backup, and
neither can this program once it has sealed one.

commands:
  --version                 print the version and exit
  keygen                    make an RSA-3072 signing keypair; print the public half
  vault create              create a vault and email its owner
  vault retention           change how many copies a vault keeps
  vault delete              end a vault: its rows, its copies, its identifier
  vault key                 show, trust or forget the fingerprint of a vault's key
  push FILE                 encrypt a file, upload it and confirm it

  datavalv keygen [--out PATH] [--force]
  datavalv vault create --external-id ID --owner-email ADDRESS [--name NAME]
                        [--locale sv|en] [--retention N]
  datavalv vault retention --external-id ID --keep N
  datavalv vault delete --external-id ID --confirm ID
  datavalv vault key --external-id ID [--trust FINGERPRINT | --forget]
  datavalv push FILE --external-id ID [--label TEXT] [--name-as NAME] [--no-name]
                     [--keep] [--idempotency-key KEY]

FILE may be - to read the backup from stdin.

${CONNECTION_HELP}

${ORDER}

${EXIT_TABLE}`;

/**
 * One screen per command, for `datavalv <command> --help`.
 *
 * Every `--help` used to print `USAGE`, so the answer to "what does vault
 * create do" was a list of five other commands with it. The Python client has
 * had per-command help since it existed, and the two READMEs promise the same
 * commands with the same flags — a reader who switches languages should not
 * find one of them explains itself and the other does not.
 *
 * The wording is the Python client's, deliberately: two texts saying the same
 * thing differently is two things to keep true.
 */
export const COMMAND_HELP: Record<CommandName, string> = {
  keygen: `usage: datavalv keygen [--out PATH] [--force]

Write an RSA-3072 private key to a file only you can read and print the public
half for pasting into /applications. The private half is never printed and
never sent anywhere.

  --out PATH                where to write it [datavalv-signing.pem]
  --force                   replace an existing key file

The file is created at mode 0600 rather than fixed afterwards, so there is no
moment at which it is readable by anybody else.`,

  "vault create": `usage: datavalv vault create --external-id ID --owner-email ADDRESS
                             [--name NAME] [--locale sv|en] [--retention N]

Create one vault and email the person who will own it.

--external-id is your own identifier for the customer, and every later call
uses it. --owner-email is the whole of the connection between the vault and
the person: there is no invitation link and no code, and the vault appears
only to an account whose *confirmed* address is identical to the one you send.

A mistyped --owner-email still returns 201, still sends a mail, and is never
reported as an error to anyone — the owner simply never sees a vault, and you
never find out. Read it back to the customer before you run this.

Until the owner signs in and starts the vault, a push answers 409 and exits 5,
which is correct and means wait.

  --external-id ID          your own identifier for the customer
  --owner-email ADDRESS     the owner's address; read it back first
  --name NAME               a name for the vault
  --locale sv|en            language of the invitation [sv]
  --retention N             how many copies to keep [1]

${CONNECTION_HELP}`,

  "vault retention": `usage: datavalv vault retention --external-id ID --keep N

Set how many copies the vault keeps, between 1 and 365.

Nothing is deleted by this call. Retention runs when the next copy is
confirmed, so lowering the number frees nothing until the next push — and a
vault that is never pushed to again keeps every copy it has.

  --external-id ID          the vault
  --keep N                  how many copies to keep, 1-365

${CONNECTION_HELP}`,

  "vault delete": `usage: datavalv vault delete --external-id ID --confirm ID

End a vault: its member rows, its backup rows and its copies in storage all
go, none of it can be recovered, and the identifier is freed for reuse.

--confirm must repeat --external-id. The service asks for the identifier twice
so that one wrong variable cannot end a customer's vault, and this does not
fill the second one in for you.

  --external-id ID          the vault to end
  --confirm ID              the same identifier again, typed out

${CONNECTION_HELP}`,

  "vault key": `usage: datavalv vault key --external-id ID [--trust FINGERPRINT | --forget]

Print the fingerprint of the key the service offers for a vault, and say
whether it is the one on record here.

The vault's owner sees the same fingerprint under their backups, worked out in
their own browser out of the key they hold. Compare the two before the first
push: they are what tells a real vault from a key somebody else substituted.
Record theirs with --trust, and every later push checks against it — a key
that changes after that stops the push rather than sealing a copy to it.

  --external-id ID          the vault
  --trust FINGERPRINT       record this fingerprint as the one to expect
  --forget                  drop the recorded fingerprint

${CONNECTION_HELP}`,

  push: `usage: datavalv push FILE --external-id ID [--label TEXT] [--name-as NAME]
                     [--no-name] [--keep] [--idempotency-key KEY]

Encrypt FILE against the vault's public key, upload the ciphertext and confirm
it. FILE may be - to read the backup from stdin.

Four calls, and all of them or none: the copy counts only once the last one
has returned, and until then the previous copy is untouched. A run that dies
halfway leaves the customer with the backup they had, never with neither.

What the service can see of a copy: its size, a digest of the ciphertext, and
--label if you send one. The filename travels encrypted with the file, so it
is readable only to the vault's members — --name-as sends a different one and
--no-name sends none at all. --label is plaintext and is not; it is for a word
like 'nightly', not for anything about the customer.

Rerun a failed push with the same --idempotency-key and the night is stored
once rather than twice.

  --external-id ID          the vault to push to
  --label TEXT              a plaintext note, visible to members
  --name-as NAME            send this as the encrypted filename instead
  --no-name                 send no filename at all, not even encrypted
  --keep                    keep this copy until a member deletes it;
                            retention never removes it
  --idempotency-key KEY     so a retried run does not store the night twice

${CONNECTION_HELP}

${EXIT_TABLE}`,
};

/** The connection flags, attached to the commands that make requests. */
const CONNECTION_OPTIONS = {
  api: { type: "string" },
  "client-id": { type: "string" },
  "key-id": { type: "string" },
  "private-key": { type: "string" },
  help: { type: "boolean", short: "h" },
} as const;

/**
 * Thrown for anything that makes the command line itself wrong. `main` turns it
 * into exit 2 with the usage line, which is what argparse does for the Python
 * client.
 */
export class UsageError extends Error {}

/** What each command accepts. One table, so `parseCommandLine` can be total. */
/**
 * Every command, with the flags it takes.
 *
 * Exported for `readme.test.ts`, which asserts the README documents all of
 * them. That test compared against a literal list it kept by hand, so a new
 * command shipped undocumented and the test stayed green -- which is the one
 * failure it exists to catch.
 */
export const COMMAND_OPTIONS: Record<CommandName, OptionConfig> = {
  keygen: {
    out: { type: "string" },
    force: { type: "boolean" },
    help: { type: "boolean", short: "h" },
  },
  "vault create": {
    ...CONNECTION_OPTIONS,
    "external-id": { type: "string" },
    "owner-email": { type: "string" },
    name: { type: "string" },
    locale: { type: "string" },
    retention: { type: "string" },
  },
  "vault retention": {
    ...CONNECTION_OPTIONS,
    "external-id": { type: "string" },
    keep: { type: "string" },
  },
  "vault delete": {
    ...CONNECTION_OPTIONS,
    "external-id": { type: "string" },
    confirm: { type: "string" },
  },
  "vault key": {
    ...CONNECTION_OPTIONS,
    "external-id": { type: "string" },
    trust: { type: "string" },
    forget: { type: "boolean" },
  },
  push: {
    ...CONNECTION_OPTIONS,
    "external-id": { type: "string" },
    label: { type: "string" },
    "name-as": { type: "string" },
    "no-name": { type: "boolean" },
    keep: { type: "boolean" },
    "idempotency-key": { type: "string" },
  },
};

export type CommandName =
  | "keygen"
  | "vault create"
  | "vault retention"
  | "vault delete"
  | "vault key"
  | "push";

export interface ParsedCommand {
  /** `undefined` means the command line asked for a help screen. */
  command: CommandName | undefined;
  /** `--version` on its own: the answer is the version, on stdout. */
  versionOnly?: boolean | undefined;
  /**
   * Which help screen, when `command` is undefined.
   *
   * `undefined` here too means the program's own: `datavalv --help`, or a
   * command line that gave no command at all.
   */
  helpFor?: CommandName | undefined;
  values: Record<string, unknown>;
  positionals: string[];
  retentionCount?: number | undefined;
}

export interface MainOptions {
  /**
   * `fetch` and `stdin` are the tests' injection seams — the counterpart of
   * `transport=` in the Python CLI's `main`. Nothing on the command line
   * reaches either of them.
   */
  fetch?: typeof globalThis.fetch;
  stdin?: () => Promise<Uint8Array>;
}

// ---------------------------------------------------------------- settings

function resolveSetting(
  value: string | undefined,
  envName: string,
  flag: string,
  what: string,
): string {
  const resolved = (value ?? process.env[envName] ?? "").trim();
  if (!resolved) {
    throw new ConfigurationError(`no ${what}: pass ${flag} or set ${envName}`);
  }
  return resolved;
}

/**
 * The signing key's PEM, off disk, complaining about a readable file.
 *
 * The mode check is a warning rather than a refusal. A key that others can read
 * is a real problem and the operator should be told at the moment they are
 * reminded it exists — but refusing to push a backup over a permission bit
 * would turn a warning into a missed night's copy, which is the worse of the
 * two.
 *
 * **The key itself is refused here, and its value is never echoed.** A PEM in
 * `DATAVALV_PRIVATE_KEY` is the mistake the variable is a path to prevent, and
 * the natural failure — `readFileSync(pem)` throwing, reported with the
 * filename in it — would print the operator's private key to stderr and into
 * whatever collects their cron output.
 */
function readPrivateKey(pathText: string): string {
  if (pathText.includes("-----BEGIN")) {
    throw new ConfigurationError(
      "the signing key was given as key text rather than as a path to it. " +
        "DATAVALV_PRIVATE_KEY names a file: a private key in an environment " +
        "variable is visible in ps, in the shell history that set it and in " +
        "any crash dump. Write it to a file with mode 600 and pass the path. " +
        "(The value is not repeated here, for the same reason.)",
    );
  }

  const keyPath = expandUser(pathText);
  let pem: string;
  try {
    pem = fs.readFileSync(keyPath, "utf8");
  } catch (exc) {
    throw new ConfigurationError(
      `cannot read the signing key at ${keyPath}: ${describeFsError(exc)}`,
    );
  }

  if (!pem.includes("-----BEGIN")) {
    throw new ConfigurationError(
      `${keyPath} does not look like a PEM key. DATAVALV_PRIVATE_KEY is a path ` +
        "to the key file, not the key.",
    );
  }

  const mode = fs.statSync(keyPath).mode;
  // Any bit for group or other. 0o077 is exactly that mask.
  if (mode & 0o077) {
    process.stderr.write(
      `warning: ${keyPath} is readable by others (mode ${(mode & 0o777)
        .toString(8)
        .padStart(3, "0")}); chmod 600 it\n`,
    );
  }
  return pem;
}

function clientFor(
  values: Record<string, unknown>,
  options: MainOptions,
): DatavalvClient {
  const api = resolveSetting(
    values["api"] as string | undefined,
    "DATAVALV_API",
    "--api",
    "API address",
  );
  const clientId = resolveSetting(
    values["client-id"] as string | undefined,
    "DATAVALV_CLIENT_ID",
    "--client-id",
    "client id",
  );
  const keyId = resolveSetting(
    values["key-id"] as string | undefined,
    "DATAVALV_KEY_ID",
    "--key-id",
    "key id",
  );
  const keyPath = resolveSetting(
    values["private-key"] as string | undefined,
    "DATAVALV_PRIVATE_KEY",
    "--private-key",
    "signing key",
  );

  return new DatavalvClient({
    apiBase: api,
    clientId,
    keyId,
    privateKey: readPrivateKey(keyPath),
    ...(options.fetch ? { fetch: options.fetch } : {}),
  });
}

// ---------------------------------------------------------------- commands

/**
 * An RSA-3072 keypair: the private half to a file only its owner can read, the
 * public half to stdout.
 *
 * **The private half is never printed and never sent anywhere.** It exists in
 * this process only long enough to be written to the descriptor `writePrivateKey`
 * opens, which is created with mode `0600` before a byte is in it — writing it
 * world-readable and then fixing the mode leaves a window in which it is
 * readable, and a window is all it takes.
 */
async function keygen(parsed: ParsedCommand): Promise<number> {
  const { values } = parsed;
  const keyPath = expandUser((values["out"] as string | undefined) ?? DEFAULT_KEY_FILENAME);

  if (fs.existsSync(keyPath) && !values["force"]) {
    process.stderr.write(
      `${keyPath} already exists. Refusing to replace a signing key that may ` +
        "still be registered — pass --force if that is what you mean, and " +
        "retire the old key in /applications afterwards.\n",
    );
    return EXIT_FAILED;
  }

  const pair = generateSigningKeypair();

  try {
    await writePrivateKey(keyPath, pair.privateKeyPem, {
      force: values["force"] === true,
    });
  } catch (exc) {
    process.stderr.write(`cannot write ${keyPath}: ${describeFsError(exc)}\n`);
    return EXIT_FAILED;
  }

  process.stdout.write(
    pair.publicKeyPem.endsWith("\n") ? pair.publicKeyPem : `${pair.publicKeyPem}\n`,
  );
  process.stderr.write(
    `\nThe private half is in ${keyPath}, mode 600, and must not leave this ` +
      "machine.\nPaste the block above into /applications in the browser — " +
      "sign in first — and\nkeep the two values it answers with:\n" +
      "  DATAVALV_CLIENT_ID  identifies this server\n" +
      "  DATAVALV_KEY_ID     identifies this key\n",
  );
  return EXIT_OK;
}

async function vaultCreate(parsed: ParsedCommand, options: MainOptions): Promise<number> {
  // `parseCommandLine` has already refused a missing or malformed value for
  // each of these, so the casts below stand on that rather than on hope.
  const { values, retentionCount } = parsed;
  const externalId = values["external-id"] as string;
  const ownerEmail = values["owner-email"] as string;
  const locale = values["locale"] as "sv" | "en" | undefined;

  const client = clientFor(values, options);
  const vault = await client.createVault(externalId, ownerEmail, {
    name: values["name"] as string | undefined,
    locale,
    retentionCount,
  });

  process.stdout.write(`${vault.tenantId}\n`);
  process.stderr.write(
    `Vault ${vault.tenantId} is ${vault.status}, and ${ownerEmail} has been emailed.\n` +
      "That address is the whole of the connection: the vault appears only to an " +
      "account\nwhose confirmed address is identical to it, and a mistyped one is " +
      "reported to\nnobody. Until the owner signs in and starts the vault, a push " +
      "answers\n409 tenant_not_initialized — which is correct, and exit code 5.\n",
  );
  return EXIT_OK;
}

async function vaultDelete(parsed: ParsedCommand, options: MainOptions): Promise<number> {
  const { values } = parsed;
  const externalId = values["external-id"] as string;
  const confirm = values["confirm"] as string;

  const deleted = await clientFor(values, options).deleteVault(externalId, { confirm });

  process.stdout.write(`${deleted.tenantId}\n`);
  process.stderr.write(
    `Vault ${deleted.tenantId} (${externalId}) is ${deleted.status}.\n` +
      "Its rows are gone and its copies are being deleted from storage. None of it\n" +
      "can be recovered, and the identifier is free for reuse.\n",
  );
  return EXIT_OK;
}

async function vaultRetention(parsed: ParsedCommand, options: MainOptions): Promise<number> {
  const { values, retentionCount } = parsed;
  const externalId = values["external-id"] as string;
  const keep = retentionCount as number;

  await clientFor(values, options).setRetention(externalId, keep);

  process.stdout.write(`${keep}\n`);
  process.stderr.write(
    `${externalId} will keep ${keep} ${keep === 1 ? "copy" : "copies"}.\n` +
      "Nothing was deleted by this. Retention runs when the next copy is confirmed,\n" +
      "so lowering the number frees nothing until the next push — and a vault that is\n" +
      "never pushed to again keeps every copy it has.\n",
  );
  return EXIT_OK;
}

async function push(parsed: ParsedCommand, options: MainOptions): Promise<number> {
  const { values, positionals } = parsed;
  const file = positionals[0] as string;
  const externalId = values["external-id"] as string;

  const { data, name } = await readPayload(file, values, options);

  const client = clientFor(values, options);
  const pushed = await client.pushBackup(externalId, data, {
    name,
    label: values["label"] as string | undefined,
    keep: values["keep"] === true,
    idempotencyKey: values["idempotency-key"] as string | undefined,
  });

  process.stdout.write(`${pushed.backupId}\n`);
  process.stderr.write(
    `${pushed.size} bytes encrypted and stored as ${pushed.backupId}` +
      (pushed.pruned ? `; ${pushed.pruned} older copy(ies) pruned` : "") +
      "\n",
  );
  if (pushed.kept) {
    process.stderr.write(
      "This copy is outside retention and will be kept until a member deletes it " +
        "or releases it.\n",
    );
  }
  if (pushed.keyFirstSeen) {
    // Once, and never again for this vault. A line repeated every night is a
    // line nobody reads, and the night it mattered would look like all the
    // others.
    process.stderr.write(
      `\nThis is the first copy this machine has pushed to ${externalId}. ` +
        "It was encrypted to the key\nthe service offered, whose fingerprint is\n\n" +
        `  ${pushed.keyFingerprint}\n\n` +
        "That key is now on record here and a different one will be refused. To know " +
        "it is the vault's\nand not merely the first one offered, ask the vault's owner " +
        "for the fingerprint shown under their backups\n-- it is worked out in their " +
        "browser from the key they hold -- and check that it is the same.\n",
    );
  }
  return EXIT_OK;
}

/**
 * Show, trust or forget the key on record for one vault.
 *
 * **`--trust` is the strongest first use there is.** The fingerprint the owner
 * reads out was worked out in their browser from the private key they hold, so
 * a pin made from it never passed through the service -- and a substituted key
 * is then refused on the first push, not the second. It and `--forget` are
 * local acts: neither makes a request.
 *
 * Plain, it prints the fingerprint of the key the service offers *now*, on
 * stdout, and records nothing. Looking is not trusting.
 */
async function vaultKey(parsed: ParsedCommand, options: MainOptions): Promise<number> {
  const { values } = parsed;
  const externalId = values["external-id"] as string;
  const api = resolveSetting(
    values["api"] as string | undefined,
    "DATAVALV_API",
    "--api",
    "API address",
  )
    .replace(/\/+$/, "")
    .replace(/\/v1$/, "");
  const clientId = resolveSetting(
    values["client-id"] as string | undefined,
    "DATAVALV_CLIENT_ID",
    "--client-id",
    "client id",
  );
  const pins = FilePins.default();

  if (values["forget"]) {
    pins.forget(api, clientId, externalId);
    process.stderr.write(
      `No key is on record for ${externalId} any more. The next push records the one ` +
        "it is offered.\n",
    );
    return EXIT_OK;
  }

  const trust = values["trust"] as string | undefined;
  if (trust !== undefined) {
    const fingerprint = trust.trim().toLowerCase().replace(/[ :]/g, "");
    if (!/^[0-9a-f]{64}$/.test(fingerprint)) {
      throw new ConfigurationError(
        "--trust takes a fingerprint: 64 hexadecimal characters, as shown under the " +
          "owner's backups",
      );
    }
    pins.set(api, clientId, externalId, fingerprint);
    process.stderr.write(
      `${fingerprint} is on record for ${externalId} in ${pins.path}. A push offered ` +
        "any other key will be refused.\n",
    );
    return EXIT_OK;
  }

  const client = clientFor(values, options);
  const offered = await publicKeyFingerprint((await client.tenantPublicKey(externalId)).publicKeyPem);
  process.stdout.write(`${offered}\n`);

  const pinned = pins.get(api, clientId, externalId);
  if (pinned === undefined) {
    process.stderr.write(
      "That is the key the service offers now. It is not on record here and this " +
        "command does not\nrecord it: compare it with the fingerprint under the " +
        "owner's backups, then either push, or\nrecord the owner's with --trust.\n",
    );
    return EXIT_OK;
  }
  if (pinned === offered) {
    process.stderr.write("It matches the key on record for this vault.\n");
    return EXIT_OK;
  }
  process.stderr.write(
    `It is NOT the key on record for this vault, which is\n  ${pinned}\n` +
      "A vault's key never changes. Do not push until you know why this one has.\n",
  );
  return EXIT_KEY_CHANGED;
}

/**
 * The file's bytes and the name to encrypt beside them.
 *
 * `-` reads stdin, which is what makes `pg_dump … | datavalv push -` work, and
 * it carries no name: there is no filename to encrypt and inventing one would
 * put a guess in the vault.
 */
async function readPayload(
  file: string,
  values: Record<string, unknown>,
  options: MainOptions,
): Promise<{ data: Uint8Array; name: string | undefined }> {
  if (file === "-") {
    const read = options.stdin ?? (async () => fs.readFileSync(0));
    return { data: await read(), name: undefined };
  }

  let data: Uint8Array;
  try {
    data = fs.readFileSync(file);
  } catch (exc) {
    throw new ConfigurationError(`cannot read ${file}: ${describeFsError(exc)}`);
  }

  if (values["no-name"]) return { data, name: undefined };
  // The basename. What directory a source server keeps its dumps in is nobody
  // else's business, and the name itself is encrypted under the backup's own
  // key either way.
  return { data, name: (values["name-as"] as string | undefined) ?? path.basename(file) };
}

// ---------------------------------------------------------------- argv

type OptionConfig = Record<string, { type: "string" | "boolean"; short?: string }>;

function parse(
  argv: string[],
  options: OptionConfig,
): { values: Record<string, unknown>; positionals: string[] } {
  try {
    const parsed = parseArgs({ args: argv, options, allowPositionals: true, strict: true });
    return { values: parsed.values as Record<string, unknown>, positionals: parsed.positionals };
  } catch (exc) {
    // `parseArgs` throws ERR_PARSE_ARGS_UNKNOWN_OPTION and friends, whose
    // messages already name the offending flag. Nothing here improves on that.
    throw new UsageError(exc instanceof Error ? exc.message : String(exc));
  }
}

function required(value: string | undefined, flag: string): string {
  if (value === undefined || value === "") {
    throw new UsageError(`${flag} is required`);
  }
  return value;
}

/**
 * The command line, checked but not acted on.
 *
 * Separate from `dispatch` so that `tests/readme.test.ts` can hand it every
 * `datavalv …` line in the README and find out whether it still parses —
 * without a key being written or a request being made. That is what
 * `build_parser()` is for in the Python client, and it is the only thing that
 * notices a flag renamed in the code and not in the document somebody copies
 * commands out of at three in the morning.
 */
export function parseCommandLine(argv: string[]): ParsedCommand {
  const [first, ...rest] = argv;

  if (first === "--help" || first === "-h") {
    return { command: undefined, values: {}, positionals: [] };
  }
  if (first === "--version") {
    return { command: undefined, versionOnly: true, values: {}, positionals: [] };
  }
  if (first === undefined) {
    throw new UsageError("a command is required: keygen, vault or push");
  }

  let command: CommandName;
  let args: string[];
  if (first === "keygen" || first === "push") {
    command = first;
    args = rest;
  } else if (first === "vault") {
    const [subcommand, ...vaultArgs] = rest;
    const vaultSubcommands = ["create", "retention", "delete", "key"];
    if (subcommand === undefined || !vaultSubcommands.includes(subcommand)) {
      throw new UsageError(
        subcommand === undefined
          ? `vault needs a subcommand: ${vaultSubcommands.join(", ")}`
          : `unknown vault subcommand ${subcommand}; they are ${vaultSubcommands.join(", ")}`,
      );
    }
    command = `vault ${subcommand}` as CommandName;
    args = vaultArgs;
  } else {
    throw new UsageError(`unknown command ${first}; expected keygen, vault or push`);
  }

  const { values, positionals } = parse(args, COMMAND_OPTIONS[command]);
  // `--help` after a command is a question about that command. It used to be
  // answered with the program's own screen, which is a list of five other
  // commands and their flags.
  if (values["help"]) return { command: undefined, helpFor: command, values, positionals };

  if (command === "keygen") {
    if (positionals.length > 0) {
      throw new UsageError(`keygen takes no positional arguments: ${positionals.join(" ")}`);
    }
    return { command, values, positionals };
  }

  if (command === "push") {
    if (positionals.length !== 1) {
      throw new UsageError(
        positionals.length === 0
          ? "push needs a FILE to push, or - to read the backup from stdin"
          : `push takes one FILE, not ${positionals.length}`,
      );
    }
    required(values["external-id"] as string | undefined, "--external-id");
    return { command, values, positionals };
  }

  if (command === "vault retention") {
    if (positionals.length > 0) {
      throw new UsageError(
        `vault retention takes no positional arguments: ${positionals.join(" ")}`,
      );
    }
    required(values["external-id"] as string | undefined, "--external-id");
    const keepText = required(values["keep"] as string | undefined, "--keep");
    const keep = Number(keepText);
    // The service's own range, refused here so a wrong number costs nothing.
    if (!Number.isInteger(keep) || keep < 1 || keep > 365) {
      throw new UsageError(`--keep must be a whole number of copies between 1 and 365, not ${keepText}`);
    }
    return { command, values, positionals, retentionCount: keep };
  }

  if (command === "vault delete") {
    if (positionals.length > 0) {
      throw new UsageError(`vault delete takes no positional arguments: ${positionals.join(" ")}`);
    }
    const externalId = required(values["external-id"] as string | undefined, "--external-id");
    const confirm = required(values["confirm"] as string | undefined, "--confirm");
    // The service's own guard, refused here so a wrong identifier costs
    // nothing. Not derived from --external-id: the point of asking twice is
    // that one wrong variable cannot end a customer's vault.
    if (confirm !== externalId) {
      throw new UsageError(
        `--confirm must repeat --external-id: expected ${externalId}, got ${confirm}`,
      );
    }
    return { command, values, positionals };
  }

  if (command === "vault key") {
    if (positionals.length > 0) {
      throw new UsageError(`vault key takes no positional arguments: ${positionals.join(" ")}`);
    }
    required(values["external-id"] as string | undefined, "--external-id");
    if (values["trust"] !== undefined && values["forget"]) {
      // argparse's mutually exclusive group, by hand.
      throw new UsageError("--trust and --forget cannot be given together");
    }
    return { command, values, positionals };
  }

  if (positionals.length > 0) {
    throw new UsageError(`vault create takes no positional arguments: ${positionals.join(" ")}`);
  }
  required(values["external-id"] as string | undefined, "--external-id");
  required(values["owner-email"] as string | undefined, "--owner-email");

  const locale = values["locale"] as string | undefined;
  if (locale !== undefined && locale !== "sv" && locale !== "en") {
    // Caught here rather than sent: `sv` and `en` are what the service composes
    // in, and its answer to a third is `invalid_request` with no field in it.
    throw new UsageError(`--locale must be sv or en, not ${locale}`);
  }

  const retentionText = values["retention"] as string | undefined;
  let retentionCount: number | undefined;
  if (retentionText !== undefined) {
    retentionCount = Number(retentionText);
    if (!Number.isInteger(retentionCount) || retentionCount < 1) {
      throw new UsageError(`--retention must be a whole number of copies, not ${retentionText}`);
    }
  }

  return { command, values, positionals, retentionCount };
}

async function dispatch(argv: string[], options: MainOptions): Promise<number> {
  const parsed = parseCommandLine(argv);

  if (parsed.versionOnly) {
    process.stdout.write(`datavalv ${VERSION}\n`);
    return EXIT_OK;
  }

  // Every run says which version it was, on stderr.
  //
  // The one fact nobody includes in a bug report, because nobody thinks of
  // it: both clients publish from a tag and an operator may be several
  // releases behind without knowing. A line in the output of the run that
  // went wrong answers it before it has to be asked.
  //
  // stderr, never stdout. stdout here is read by machines — the tenant id
  // from `vault create`, the fingerprint from `vault key`, which the README
  // compares in a one-line shell test — and a banner on it turns every such
  // comparison false. A help screen is asked for, so it is not a run.
  if (parsed.command !== undefined) {
    process.stderr.write(`datavalv ${VERSION}\n`);
  }

  if (parsed.command === undefined) {
    // Asked for, so it is output: stdout, exit 0. `datavalv --help | less` is
    // the point, and it is also where the exit-code table lives, so an operator
    // reading a 5 at three in the morning does not have to find the README.
    const screen = parsed.helpFor === undefined ? USAGE : COMMAND_HELP[parsed.helpFor];
    process.stdout.write(`${screen}\n`);
    return EXIT_OK;
  }
  if (parsed.command === "keygen") return keygen(parsed);
  if (parsed.command === "push") return push(parsed, options);
  if (parsed.command === "vault key") return vaultKey(parsed, options);
  if (parsed.command === "vault retention") return vaultRetention(parsed, options);
  if (parsed.command === "vault delete") return vaultDelete(parsed, options);
  return vaultCreate(parsed, options);
}

/** Run one command and answer with its exit code. */
export async function main(argv?: string[], options: MainOptions = {}): Promise<number> {
  const args = argv ?? process.argv.slice(2);

  try {
    return await dispatch(args, options);
  } catch (exc) {
    if (exc instanceof UsageError) {
      process.stderr.write(`datavalv: ${exc.message}\n\n${USAGE}\n`);
      return EXIT_USAGE;
    }
    if (exc instanceof ConfigurationError) {
      process.stderr.write(`datavalv: ${exc.message}\n`);
      return EXIT_CONFIG;
    }
    if (exc instanceof AuthError) {
      process.stderr.write(`datavalv: ${exc.message}\n`);
      return EXIT_AUTH;
    }
    if (exc instanceof VaultKeyChanged) {
      process.stderr.write(`datavalv: ${exc.message}\n`);
      return EXIT_KEY_CHANGED;
    }
    if (exc instanceof DatavalvError) {
      process.stderr.write(`datavalv: ${exc.message}\n`);
      if (exc.retryable) return EXIT_RETRY;
      return exc instanceof ApiError ? EXIT_REFUSED : EXIT_FAILED;
    }
    if (exc instanceof RangeError) {
      // A field this client checked before sending: an over-long label, a name
      // that will not fit the encrypted-filename field.
      process.stderr.write(`datavalv: ${exc.message}\n`);
      return EXIT_FAILED;
    }
    throw exc;
  }
}

// ---------------------------------------------------------------- odds

function expandUser(text: string): string {
  if (text === "~") return process.env["HOME"] ?? text;
  if (text.startsWith("~/")) {
    const home = process.env["HOME"];
    return home ? path.join(home, text.slice(2)) : text;
  }
  return text;
}

/**
 * What went wrong, without the path. Node puts the filename in `err.message`
 * ("ENOENT: no such file or directory, open '…'"), and for the signing key that
 * filename is sometimes the key itself — see `readPrivateKey`.
 */
function describeFsError(exc: unknown): string {
  if (exc !== null && typeof exc === "object" && "code" in exc) {
    const code = String((exc as { code: unknown }).code);
    return FS_REASONS[code] ?? code;
  }
  return exc instanceof Error ? exc.name : String(exc);
}

const FS_REASONS: Record<string, string> = {
  ENOENT: "no such file or directory",
  EACCES: "permission denied",
  EISDIR: "is a directory",
  ENOTDIR: "not a directory",
  EEXIST: "file already exists",
  ELOOP: "too many symbolic links",
  ENOSPC: "no space left on device",
  EPERM: "operation not permitted",
};
