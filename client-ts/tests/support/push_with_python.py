"""Drive the **Python** client's `push_backup` against a URL, for the interop test.

`client-ts/tests/interop.test.ts` stands up a real HTTP server and runs this
against it, so that the bytes it captures were produced by
`datavalv_client.DatavalvClient` doing a genuine four-call push — not by a
re-implementation of the format written on this side of the language boundary,
which would agree with itself and prove nothing.

The plaintext arrives on stdin and a JSON summary leaves on stdout; the point of
the run is what the server recorded, not what this prints.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from datavalv_client import DatavalvClient


def main() -> int:
    parser = argparse.ArgumentParser(prog="push_with_python")
    parser.add_argument("--api", required=True)
    parser.add_argument("--external-id", required=True)
    parser.add_argument("--name")
    parser.add_argument("--label")
    args = parser.parse_args()

    # The same environment variables the CLI reads, and the same rule: the
    # signing key is a PATH. The interop test writes it at mode 600 and passes
    # the path, which is also how a real scheduled job is configured.
    key_path = os.environ["DATAVALV_PRIVATE_KEY"]
    with open(key_path) as handle:
        private_key_pem = handle.read()

    with DatavalvClient(
        args.api,
        os.environ["DATAVALV_CLIENT_ID"],
        os.environ["DATAVALV_KEY_ID"],
        private_key_pem,
    ) as client:
        pushed = client.push_backup(
            args.external_id,
            sys.stdin.buffer.read(),
            name=args.name,
            label=args.label,
        )

    json.dump(
        {
            "backupId": pushed.backup_id,
            "size": pushed.size,
            "sha256": pushed.sha256,
            "keyId": pushed.key_id,
        },
        sys.stdout,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
