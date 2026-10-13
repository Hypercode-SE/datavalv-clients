# Datavalv clients

The client libraries for [Datavalv](https://datavalv.se), an end-to-end
encrypted backup service, and the file format they share.

| Directory | Package |
|---|---|
| `client/` | `datavalv-client` (PyPI) |
| `client-ts/` | `@datavalv/client` (npm) |
| `crypto/` | `@datavalv/crypto` (npm) |
| `format/` | the on-disk format, specified byte by byte, with test vectors |

Each package has its own README with the procedure for connecting a server.

## This repository is a mirror

It is published from Datavalv's development repository, which is private
because it also holds the service. **Pull requests here cannot be merged** —
the source lives elsewhere. Issues and questions are welcome, and anything
accepted is applied upstream and appears here on the next publish.

The point of the mirror is that you can read the code that encrypts your
backups, and check the format against your own implementation, without taking
either on trust.

## Licence

MIT. See the `LICENSE` file in each package.
