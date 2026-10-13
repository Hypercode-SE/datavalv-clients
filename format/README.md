# Datavalv wire format

`v1.json` is the single source of truth for every constant in the Datavalv
ciphertext format. Both the Python client and the TypeScript web client
generate their constants from it; neither declares them.

## Changing a constant

You almost certainly cannot. Once a real backup exists, v1 is immutable: a
changed constant makes previously stored backups unreadable.

The only legal change is to define a new version alongside v1:

1. Add `v2.json` with the new constants and a new `version` byte.
2. Generate a new vector set under `vectors/v2/`.
3. Keep v1 readable in both implementations, forever.

`check_freeze.py` enforces this by comparing `v1.json` against `v1.lock` in CI.
