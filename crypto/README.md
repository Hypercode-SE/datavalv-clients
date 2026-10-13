# @datavalv/crypto

Datavalv's v1 backup format, on its own: AES-256-GCM content encryption,
RSA-OAEP key wrapping, and the Argon2id derivation a member's browser runs.

**You probably do not want to install this.** It is a dependency of
[`@datavalv/client`](https://www.npmjs.com/package/@datavalv/client), which is
what a server pushing backups uses, and of the Datavalv web client, which is
what opens them again. Both pull it in for you. Install it directly only if you
are reading or writing v1 blobs yourself — verifying that a backup really is
encrypted the way we say, for instance.

```bash
npm install @datavalv/crypto
```

Node 22 or newer, or any browser with Web Crypto. ESM only. No framework
dependency, deliberately: it is separated from the Angular application so that
the format implementation cannot acquire one by accident, and so the
conformance CLI can run under plain Node.

## What it is for

Datavalv receives backups pushed by a server and hands them back to people in a
browser. The copy is encrypted on the machine that made it, under a key
Datavalv never holds, so neither Datavalv nor AWS can read it. This package is
the part that does the encrypting and decrypting — everything that happens
before a byte is sent and after one comes back.

It talks to nothing. There is no HTTP in here, no configuration, and no
credentials: it takes bytes and keys and returns bytes and keys. The four HTTP
calls one backup costs live in `@datavalv/client`.

## The format is specified, not merely implemented

`format/v1.json` in the source tree is the single definition both
implementations are generated from, and it is frozen — `v1.lock` records the
hash and a check refuses any change to it. There is a Python implementation of
the same format in [`datavalv-client`](https://pypi.org/project/datavalv-client/),
and the two are not merely believed to agree: a conformance matrix encrypts
with each and decrypts with the other on every test run, across ASCII, accented
and non-Latin inputs, and checks that a tampered blob is refused by both.

So a backup written by the Python client opens in a browser, and one written in
a browser opens with the Node client. That is a tested fact rather than an
intention.

## What is in it

| | |
|---|---|
| Content | `encryptBackup`, `decryptBackup` — AES-256-GCM, one message and one tag per blob |
| Key wrapping | RSA-3072-OAEP with an **empty label**, which is the detail most likely to trip a reimplementation |
| Derivation | Argon2id over the address as salt, then HKDF into a login hash and a key-encrypting key |
| Header | `encodeHeader`, `decodeHeader`, `FormatError` |
| Encoding | `b64encode`, `b64decode`, `derToPem`, `pemToDer` |
| Invitations | `deriveInviteKey` |

`Bytes` is `Uint8Array<ArrayBuffer>` throughout; the package never hands you a
view onto a buffer it still holds.

## Licence

MIT. Copyright Hypercode AB.

The source is at
<https://github.com/Hypercode-SE/datavalv-clients/tree/main/crypto>.
