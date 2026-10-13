# Changelog

What changed in each release of `datavalv-client` and the `datavalv` command
it installs, newest first. The date is the day the release was prepared; the
tag `client-vX.Y.Z` is what publishes it to PyPI.

The TypeScript client, `@datavalv/client`, speaks the same protocol with the
same commands and keeps its own changelog in `client-ts/CHANGELOG.md`.

## 0.7.0 — 2026-10-13

### Added

- **Keeping a copy outside retention.** `push_backup(..., keep=True)` and
  `datavalv push --keep` ask the service to hold this copy until a member of
  the vault deletes it. Retention never removes a kept copy and it takes no
  place in the vault's retention count, so the nightly rotation is not
  shortened by it. It still counts towards the storage allowance, and a kept
  copy that would not fit is refused before anything is uploaded.
  `PushedBackup.kept` says whether the push asked for it, and `datavalv push`
  says so on stderr.
- Only a vault member can release a kept copy, from their own screen. This
  client can ask for a copy to be kept but has no way to release one, on
  purpose: a signing key on an unattended server should not decide that a
  copy may be deleted.

Use it for the dump taken before an upgrade or a migration, not on the
nightly schedule: a vault that keeps every copy fills up and starts refusing.

### Unchanged

- An ordinary push sends exactly the body it sent in 0.6.0.

## 0.6.0 — 2026-09-24

### Added

- `set_retention(external_id, count)` and
  `datavalv vault retention --external-id ID --keep N`: change how many copies
  an existing vault keeps. A count outside 1–365 is refused before a request
  is made. Nothing is deleted by the call; retention runs when the next copy is
  confirmed.
- `delete_vault(external_id, confirm=...)` and
  `datavalv vault delete --external-id ID --confirm ID`: end a vault. `confirm`
  is required and never derived from the identifier.
- `--version`, and every run states its version on stderr before anything
  else.

### Changed

- Every command has a help screen that explains it. `vault create` warns about
  a mistyped owner address before the call rather than after it, the top-level
  `--help` gives the four steps of connecting a server in order, and `push`
  says what the service can and cannot see of a copy.

## 0.5.1 — 2026-09-23

### Changed

- A private key in any value a request carries — `--label`, `--name-as`, a
  `name=` argument — is refused before the request is made, as a
  `ConfigurationError` (exit 3). Every PEM label is caught in any case, and so
  is PuTTY's own format.

## 0.5.0 — 2026-09-22

The first release on PyPI.

- `DatavalvClient`: create a vault, list its backups, and push a backup —
  encrypt, register, upload and confirm — in one call, `push_backup`.
- The `datavalv` command: `keygen`, `vault create`, `vault key` and `push`,
  with documented exit codes so a schedule can branch on them; 5 means
  "nothing is wrong, run it again later".
- Key pinning: the first key a vault offers is recorded, and a different one
  is refused with `VaultKeyChanged` (exit 7) before anything is encrypted.
  `vault key --trust` records the fingerprint the vault's owner reads out, and
  `--forget` drops it.
- The v1 backup format, AES-256-GCM with RSA-OAEP key wrapping, byte-for-byte
  compatible with the TypeScript client.
