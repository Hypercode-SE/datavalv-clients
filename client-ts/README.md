# @datavalv/client

Datavalv receives backups pushed by a server and hands them back to people in a
browser. The copy is encrypted on the machine that made it, under a key
Datavalv never holds, so neither Datavalv nor AWS can read it.

This package is the pushing half, for a server that runs Node: a `datavalv`
command for a scheduled job, and a `DatavalvClient` for a program that would
rather do it itself. It is the procedure on <https://datavalv.se/connect-system>
with the mechanical parts done for you — the keypair, a fresh single-use JWT for
every request, and the four HTTP calls one backup costs, in order, with the
checksum header the third one requires.

One step is not a command, and never will be. Step 3 says why.

This is the same client as `datavalv-client` for Python: the same three
commands, the same flags, the same exit codes and the same format. Either will
do; a shop running both can write one rule in one scheduler. That the two agree
is not a hope — a backup produced by one is decrypted by the other on every test
run.

Node 22 or newer, on a POSIX system. ESM only.

---

## Connecting a server

Six steps. The first four are once per server; the last two are what you do per
customer and per night.

### 1. Install it

```bash
npm install @datavalv/client
```

That is the whole step for most people. `@datavalv/crypto` comes with it as a
dependency; you never install it yourself.

The source is public if you would rather read it before you run it, or build it
yourself:

```bash
git clone https://github.com/Hypercode-SE/datavalv-clients.git
cd datavalv-clients
( cd crypto    && npm install && npm pack --pack-destination .. )
( cd client-ts && npm install && npm pack --pack-destination .. )
```

`crypto` first: installing `client-ts` builds it against the package beside it.

That writes two tarballs at the repository root:

```
datavalv-crypto-0.7.0.tgz
datavalv-client-0.7.0.tgz
```

Copy both to the server and install them together:

```bash
npm install ./datavalv-client-0.7.0.tgz ./datavalv-crypto-0.7.0.tgz
```

Both, in one command, on purpose. `@datavalv/crypto` holds the backup format and
is a **peer** dependency: there must be exactly one copy of it in a tree, or a
backup written by one copy could be read by another. npm would fetch it for you
once it is published; until then you hand it over.

It brings `jose` with it and installs one command, `datavalv` — as
`node_modules/.bin/datavalv`, which `npx datavalv` and an npm script will find.

### 2. Make a signing keypair

Run this **on the machine that will push the backups**. A signing key that has
been copied from somewhere else has been in an `scp` buffer, a backup of a
laptop, and whatever else copied it.

```bash
datavalv keygen
```

It writes `datavalv-signing.pem` in the current directory — created at mode
`600`, not created and then chmodded, because a file that exists readable for a
moment has been readable — and prints the **public** half to stdout, which is
the block you paste in step 3. Everything else it says goes to stderr.

The private half is never printed, never sent anywhere, and Datavalv stores only
the public one: there is no secret to fetch back later, and nothing we hold
proves anything in your place.

`--out PATH` puts the key somewhere else. `keygen` refuses to overwrite an
existing key file, because the old one may still be registered and pushing
backups; `--force` means you know that, and the old key should be retired in the
browser afterwards.

### 3. Register the server in the browser

Sign in at <https://datavalv.se>, open **Connected servers** in the account menu
(`/applications`), give the server a name and paste the whole public block from
step 2. Two values come back. Keep both:

| value | what it identifies |
|---|---|
| `clientId` | this server |
| `kid` | this key |

**The first time that account signs in, a recovery code comes first.** Every new
account is shown one, once, and the screen asks for two of its four groups back
before it lets you on — an account that will only ever own a server included.
Write it down and keep it off the machine, then go on to **Connected servers**.
It is what ties the account's own key to a new password if the old one is lost.

**Why this is not a command.** `POST /v1/apps` sits on the Cognito authorizer,
so it takes a signed-in person — and a command line that asked for your Datavalv
password would be asking for the one password this product is built never to
see. That password never reaches Datavalv at all: the browser turns it into a
key that unwraps a vault and sends only a value derived from it, which is why a
stolen copy of our database is unreadable. A CLI prompt would be the one place
it existed in the clear. So this client makes the keypair and prints the public
half, and a human pastes it.

The same screen is where a key is rotated — add the new one, deploy it, retire
the old one, with both working in between — and where a server is retired
altogether.

### 4. Configure the four settings

| variable | flag | value |
|---|---|---|
| `DATAVALV_API` | `--api` | `https://api.datavalv.se` (staging is `https://api-staging.datavalv.se`, and a registration in one is unknown to the other) |
| `DATAVALV_CLIENT_ID` | `--client-id` | the `clientId` from step 3 |
| `DATAVALV_KEY_ID` | `--key-id` | the `kid` from step 3 |
| `DATAVALV_PRIVATE_KEY` | `--private-key` | the **path** to the key from step 2 |

A flag wins over the variable; a scheduled job should use the variables.

`DATAVALV_PRIVATE_KEY` is a path on purpose. A private key in an environment
variable is in `ps`, in the shell history of whatever set it, and in every crash
dump of the process that read it. The client refuses key text there rather than
being helpfully permissive about it, and does not echo the value back when it
does — the natural error message would print your private key into whatever
collects your cron output.

If the key file is readable by anyone but its owner you get a warning, not a
refusal: a permission bit is worth telling you about, and not worth turning into
a night with no backup.

### 5. Create a vault for the customer

One vault per customer, organisation or server whose data you push. One call,
once.

```bash
datavalv vault create --external-id kund-4711 --owner-email anna@example.se --name "Kund 4711" --retention 7
```

`--external-id` is your own identifier for them and what every later call uses.
`--retention` is how many copies are kept (1 if you do not say), and it can be
changed later. `--locale sv|en` picks the language of the invitation the owner
receives — supplied, never detected, because no browser is involved in this call
and Swedish is the default guess.

To change how many copies an existing vault keeps:

```bash
datavalv vault retention --external-id kund-4711 --keep 12
```

Nothing is deleted by that call. Retention runs when the next copy is
confirmed, so lowering the number frees nothing until the next push — and a
vault that is never pushed to again keeps every copy it has.

To end a vault:

```bash
datavalv vault delete --external-id kund-4711 --confirm kund-4711
```

Its member rows, its backup rows and its copies in storage all go, none of it
can be recovered, and the identifier is freed for reuse. `--confirm` must
repeat `--external-id` and is not filled in for you: the service asks for the
identifier twice so that one wrong variable cannot end a customer's vault, and
a client that derived the second from the first would be the one
implementation of that guard which cannot fail.

The vault's id is printed on stdout; the rest is on stderr. The owner is
emailed, and the vault waits.

**The address is the whole of the connection.** There is no invitation link and
no code: the vault appears only to an account whose *confirmed* email address is
identical to the one you sent. A mistyped address still returns `201`, still
sends a mail, and is reported as an error to nobody. Read it back to the
customer before you run the command.

**The invitation names your system only once we have confirmed who registered
it.** Anybody can register a server under any name, and that mail goes out from
our domain — so until we have checked, it says only that a vault is waiting, and
carries neither your server's name nor the vault's. Get in touch once the server
is registered and we will do it; nothing else changes.

**Creations are counted per day.** A server may create twice as many vaults in a
day as it may hold — ten, at the default allowance of five — and deleting a vault
gives nothing back. Past that the call answers `429 quota_exceeded`, which is
exit code 5: tomorrow it works.

### 6. Check the vault's key

Every backup is encrypted to the vault's public key, and step 1 of a push gets
that key **from us**. We are the one party this design does not trust with your
plaintext, so that key is the one thing here you should not take our word for: a
service that answered with a key of its own could read every backup sent
afterwards, and nothing in the protocol would show it.

So this client remembers. The first key it is given for a vault is written down,
as `ssh` does with `known_hosts`, and **a different one is refused before
anything is encrypted** — exit code 7. A vault's key is made once, in its first
member's browser, and never changes.

That leaves the first time, and a person closes it. Once the owner has started
the vault:

```bash
datavalv vault key --external-id kund-4711
```

prints the fingerprint of the key we offer, on stdout, and records nothing. The
vault's owner sees a fingerprint under their backups at datavalv.se, **worked out
in their browser from the key they hold** — ask them to read it out. If the two
are the same, push. Better still, record theirs, which makes no request and
never passes through us at all:

```bash
datavalv vault key --external-id kund-4711 --trust de6272b8151979389437054b06df8a817a6ad62ab87faac4bbacb3360c1385d0
```

A substituted key is then refused on the very first push. Skip both and the
first push trusts the key it is offered, prints its fingerprint once, and pins
it — better than nothing, and the check above is what makes it more than that.

The fingerprint is SHA-256 over the key's DER, so nothing of ours is needed to
compute it:

```bash
openssl pkey -pubin -in tenant-public.pem -outform DER | openssl dgst -sha256
```

Pins live in `~/.local/state/datavalv/known_vaults.json` (under
`$XDG_STATE_HOME` if that is set), mode 600; `DATAVALV_KNOWN_VAULTS` names
another path. The Python and TypeScript clients share the file. **A machine with
no disk to remember on** — a container that starts empty every night — sees every
key for the first time, which protects nothing: mount that path, or pass the
fingerprint in from configuration (see *The library*).

**If a push exits 7**, nothing was sent. If the vault was deleted and created
again it is a new vault with a new key: get the new fingerprint from its owner,
and if it is the one offered,

```bash
datavalv vault key --external-id kund-4711 --forget
```

and push again. If it is not, do not push, and tell us.

### 7. Push a backup

```bash
datavalv push /var/backups/kund-4711.sql.gz --external-id kund-4711 --label "nightly"
```

That is the four calls: fetch the vault's public key, register the copy, upload
the ciphertext, confirm it. All four or none — a copy counts only once the last
one has returned, and until then the previous copy is untouched.

The backup id goes to stdout and everything else to stderr, so
`BACKUP=$(datavalv push ...)` holds an id and nothing else. A dash reads stdin,
for a dump you would rather not write to disk:

```bash
pg_dump kund4711 | gzip | datavalv push - --external-id kund-4711
```

The filename is encrypted and sent along, so the member who can open the backup
can see what it was called. `--name-as NAME` sends a different one and
`--no-name` sends none at all; reading from stdin sends none, because there is
no name to send and inventing one would put a guess in the vault. A path is
never sent — only its last component.

`--idempotency-key` is worth setting from a schedule that retries: without it, a
retry of a run that timed out stores the same night twice and spends the quota
twice.

`--keep` holds this copy outside retention: it takes no place in the vault's
retention count and stays until a member deletes it or releases it from their
own screen. Use it for the dump taken before an upgrade or a migration, not on
the nightly schedule — a kept copy still counts towards the vault's storage
allowance, and a vault that keeps every night fills up and starts refusing.

**A `409` before the owner has started the vault is expected.** The vault's key
is made in the first member's browser, so until somebody signs in there is
genuinely nothing to encrypt against. `datavalv push` exits **5** for that, and
5 means *nothing is wrong, run it again later*. A schedule that treats it as a
failure pages somebody about a server that is working perfectly. The run after
the owner signs in goes through on its own, with nobody touching the server.

---

## Exit codes

`datavalv` returns these so a scheduled job can branch on them without reading
prose. They are the Python client's codes, value for value:

| code | meaning |
|---|---|
| 0 | done |
| 1 | failed for a reason not covered below |
| 2 | the command line was wrong |
| 3 | a setting, or a file named on the command line, is missing or unusable |
| 4 | the signing key, client id or key id was refused |
| 5 | nothing is wrong; run it again later (vault not started yet, network, quota) |
| 6 | the service refused the request and a person must look at it |
| 7 | the key offered for the vault is not the one on record; nothing was sent |

5 is the one worth a rule in your scheduler: run it again unchanged, and the run
after the vault is started goes through. 3, 4, 6 and 7 need a person — 7 most
of all, and soon: see step 6. 2 means the command line itself was wrong, so
nobody was going to be paged about it anyway.

## What it says about itself

Every run writes `datavalv <version>` to stderr before it does anything else.
It is there so that the output of a run that went wrong already answers the
first question anybody will ask about it: both clients publish from a tag, and
an operator can be several releases behind without knowing. `datavalv
--version` on its own prints the same string to stdout and exits 0.

Nothing else about a run reaches stdout except the value the command produces —
the vault's id from `vault create`, the fingerprint from `vault key`, the
number from `vault retention`. Everything advisory is on stderr, so
`FINGERPRINT=$(datavalv vault key --external-id kund-4711)` captures a
fingerprint and not a banner.

Every command explains itself: `datavalv <command> --help` is a screen about
that command, and `datavalv --help` carries the order the four steps happen in
and the exit codes above.

---

## What the crypto does

Per backup, on your server, before anything is sent:

- A fresh **AES-256-GCM** key is drawn for this one copy and the file is
  encrypted under it. The whole 21-byte format header — magic bytes, version
  and algorithm ids, the IV and its length — is the additional authenticated
  data, so a header edited in transit makes the copy fail to open rather than
  decrypt into something else.
- That key is wrapped to the **vault's RSA-3072 public key**, RSA-OAEP with
  SHA-256, and the wrapped copy travels with the backup. The vault's private
  key exists only inside members' browsers, wrapped under keys derived from a
  member's password and their recovery code.
- A **SHA-256 digest is taken over the ciphertext**, never over the plaintext.
  It is signed into the upload URL, so storage refuses a body that disagrees
  with it, and Datavalv checks it again before the copy is allowed to count.
- The filename, when you send one, is encrypted under the same key with its own
  IV — never the payload's, which would reuse a nonce under one AES-GCM key.

None of that is written here. It is `@datavalv/crypto`, the package the browser
uses to *read* the backups this one writes — one implementation of the bytes,
at both ends. `format/v1.json` in this repository is the frozen definition, and
a conformance matrix runs the TypeScript and the Python against each other on
live code.

Nothing here can open a backup you have pushed — not for want of code, since
`@datavalv/crypto` exports `decrypt` and `unwrapDek`, but because a source
application is never handed the key it would need. That is what makes a
compromised server leak the backups it is about to make rather than the ones it
has made.

---

## The library

The CLI is a thin layer over this. Everything it does is available directly:

```typescript
import { readFile } from "node:fs/promises";

import { DatavalvClient } from "@datavalv/client";

const client = new DatavalvClient({
  apiBase: "https://api.datavalv.se",
  clientId: CLIENT_ID,
  keyId: KEY_ID,
  privateKey: await readFile("/etc/datavalv/datavalv-signing.pem", "utf8"),
});

const vault = await client.createVault("kund-4711", "anna@example.se", {
  retentionCount: 7,
});

const pushed = await client.pushBackup(
  "kund-4711",
  await readFile("/var/backups/kund-4711.sql.gz"),
  { name: "kund-4711.sql.gz", label: "nightly" },
);

console.log(pushed.backupId, pushed.size, pushed.sha256);
```

There is nothing to close: the client holds no connection pool of its own, only
Node's `fetch`. Pass your own `fetch` if you need a proxy agent or a different
dispatcher.

`privateKey` is PEM **text** or an already-loaded `KeyObject` — never a path,
which is the opposite of the environment variable's rule and for the same
reason: a client that accepted both would make the two spellings
interchangeable, and that is how a key ends up in an environment variable.

`pushBackup` takes the bytes, in memory. The size and the digest of the
ciphertext have to be known before an upload URL can be asked for, so there is
no streaming arrangement that would not encrypt the file twice.

Failures are `DatavalvError` subclasses, each naming the step it happened at,
and each saying whether running the same thing again could work:

```typescript
import { DatavalvError } from "@datavalv/client";

try {
  await client.pushBackup("kund-4711", data);
} catch (error) {
  if (error instanceof DatavalvError && error.retryable) {
    // VaultNotInitialized, QuotaExceeded, NetworkError
    log.info("not yet: %s", error.message);
  } else {
    // AuthError, ConfigurationError, ApiError, UploadError,
    // VaultKeyChanged -- never retry that one; see step 6
    throw error;
  }
}
```

**The vault's key is pinned here too**, with no option needed: `pins` defaults
to the same file the CLI uses, and `pushBackup` throws `VaultKeyChanged` — with
`.pinned` and `.offered` — before encrypting anything if the key is not the one
on record. `pushed.keyFirstSeen` is true on the push that recorded it, and
`pushed.keyFingerprint` is what to compare with the owner's. On a machine with
no disk to remember on, pass the fingerprint in from configuration instead, so
that a key which is not that one is refused from the first push:

```typescript
import { DatavalvClient, MemoryPins } from "@datavalv/client";

const pins = new MemoryPins([[["https://api.datavalv.se", CLIENT_ID, "kund-4711"], FINGERPRINT]]);
const client = new DatavalvClient({
  apiBase: "https://api.datavalv.se",
  clientId: CLIENT_ID,
  keyId: KEY_ID,
  privateKey: PRIVATE_KEY_PEM,
  pins,
});
```

`client.listBackups("kund-4711")` says what the service holds for a vault: ids,
sizes, digests, timestamps, labels and the encrypted filename. No key material —
the member listing is a different model in the API for exactly that reason.

---

## What is not here

- **Restoring is the browser's.** A backup is decrypted inside a member's
  browser with a key this package is never given. Signing in at datavalv.se is
  the whole of the restore path.
- **Registering a server is the browser's**, for the reason in step 3.
- **Changing retention and deleting a vault** are API routes
  (`PATCH` and `DELETE /v1/tenants/{externalId}`) that this client does not wrap
  yet. Retention is set when the vault is created.

The protocol underneath, if you would rather implement it yourself, is
<https://datavalv.se/developers> — and the four calls with their fields are on
<https://datavalv.se/connect-system>, which this README follows step for step.

---

## Developing and releasing

The package lives in `client-ts/` of the Datavalv monorepo. Its tests run with
`cd client-ts && npm test`, and `make check` from the repository root runs those
plus the Python client, the browser suite and the format governance both depend
on.

`npm test` rebuilds `@datavalv/crypto` first. This package resolves it the way a
consumer does — through `dist/` — so a stale build would otherwise be tested
instead of the source beside it.

`RELEASING.md` is the publish procedure. It has not been run: nothing has been
uploaded to npm under either name by this project.
