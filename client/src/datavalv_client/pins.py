"""Which key each vault was first seen with, so that a different one is refused.

**The service hands out the key every backup is encrypted to, and the service is
the one party this design does not trust with plaintext.** Step 1 of a push is
`GET /v1/tenants/{externalId}/public-key`. A server that answered it with a key
of its own would read every backup pushed from then on, and nothing in the
protocol could show it: no signature from the server helps when the server is
the adversary, and `keyId` is the server's own value.

What does help is memory. A vault's key is made once, in its first member's
browser, and never changes, so the first key this machine is given for a vault
is either the vault's or an attack that was already under way -- and every later
one has to be the same. This module is that memory, in the shape of SSH's
`known_hosts`: trust on first use, written down, and a refusal afterwards.

**First use is the part a person closes.** The fingerprint
(`crypto.public_key_fingerprint`) is defined so that `openssl` computes it, and
the vault's owner is shown theirs under their backups, worked out in their
browser from the private key they hold. Compared once, the pin stops being
"whatever we were first told" and becomes "the vault's key".

The file is JSON, one entry per vault, and is the same file `@datavalv/client`
writes -- one machine may run either client, or both:

    {"version": 1,
     "vaults": {"<api base> <client id> <external id>": {"fingerprint": "<64 hex>"}}}

The scope is all three, because `kund-4711` on staging and on production are
different vaults, and so is another application's `kund-4711`.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Protocol

from .errors import ConfigurationError

#: Where `FilePins.default()` keeps its file unless `DATAVALV_KNOWN_VAULTS` says
#: otherwise. State, not configuration: nobody edits it, and losing it costs a
#: second first-use rather than a broken setup.
ENV_VAR = "DATAVALV_KNOWN_VAULTS"
_VERSION = 1


def _scope(api_base: str, client_id: str, external_id: str) -> str:
    return f"{api_base} {client_id} {external_id}"


class KeyPins(Protocol):
    """Somewhere a fingerprint can be remembered between pushes."""

    def get(self, api_base: str, client_id: str, external_id: str) -> str | None: ...

    def set(self, api_base: str, client_id: str, external_id: str, fingerprint: str) -> None: ...


class MemoryPins:
    """Pins that live as long as this object.

    Two uses. A long-running process that keeps its own state and hands the
    same `MemoryPins` to every client it builds. And a machine with no disk to
    remember on -- a container that starts empty every night sees every key for
    the first time, which is no protection at all -- whose operator compares
    the fingerprint once and passes it in from configuration:

        MemoryPins({(api_base, client_id, "kund-4711"): "de6272b8..."})

    A vault whose key is not that one is then refused from the first push.
    """

    def __init__(self, known: dict[tuple[str, str, str], str] | None = None) -> None:
        self._pins = {_scope(*scope): fingerprint for scope, fingerprint in (known or {}).items()}

    def get(self, api_base: str, client_id: str, external_id: str) -> str | None:
        return self._pins.get(_scope(api_base, client_id, external_id))

    def set(self, api_base: str, client_id: str, external_id: str, fingerprint: str) -> None:
        self._pins[_scope(api_base, client_id, external_id)] = fingerprint

    def forget(self, api_base: str, client_id: str, external_id: str) -> None:
        self._pins.pop(_scope(api_base, client_id, external_id), None)


class FilePins:
    """Pins in a JSON file that only its owner can read.

    Read on every `get` and rewritten whole on every `set`, through a temporary
    file and a rename, so a push that is killed mid-write leaves the old file
    and not half of a new one. Two pushes that pin two *different* vaults in
    the same instant can lose one entry to the other's rename; the loser is
    pinned again on its next push, which is a second first-use and nothing
    worse.

    **A file that cannot be read as a pin file stops the push.** Treating a
    corrupt or unreadable file as an empty one would turn "somebody damaged the
    pin file" into "every key is new, carry on" -- the attack with one extra
    step.
    """

    def __init__(self, path: str | os.PathLike[str]) -> None:
        self.path = Path(path).expanduser()

    @classmethod
    def default(cls) -> FilePins:
        """`$DATAVALV_KNOWN_VAULTS`, else the user's state directory."""
        explicit = os.environ.get(ENV_VAR, "").strip()
        if explicit:
            return cls(explicit)
        state = os.environ.get("XDG_STATE_HOME", "").strip() or "~/.local/state"
        return cls(Path(state) / "datavalv" / "known_vaults.json")

    def _read(self) -> dict[str, dict[str, str]]:
        try:
            text = self.path.read_text()
        except FileNotFoundError:
            return {}
        except OSError as exc:
            raise ConfigurationError(
                f"cannot read the known-vaults file at {self.path}: {exc.strerror or exc}. "
                f"Set {ENV_VAR} to a path this user can read and write."
            ) from exc
        try:
            document = json.loads(text)
            vaults = document["vaults"]
            if document["version"] != _VERSION or not isinstance(vaults, dict):
                raise ValueError("not a version 1 known-vaults file")
            return vaults
        except (ValueError, KeyError, TypeError) as exc:
            raise ConfigurationError(
                f"{self.path} is not a known-vaults file ({exc}). It is not treated as "
                "empty: that would accept any key for every vault. Look at why it "
                "changed, then restore or remove it."
            ) from exc

    def _write(self, vaults: dict[str, dict[str, str]]) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            # `mkstemp` creates at 0600, so the entries are never readable by
            # anybody else, not even for the moment before a chmod.
            fd, temporary = tempfile.mkstemp(dir=self.path.parent, prefix=".known_vaults.")
            try:
                with os.fdopen(fd, "w") as handle:
                    json.dump({"version": _VERSION, "vaults": vaults}, handle, indent=1)
                    handle.write("\n")
                os.replace(temporary, self.path)
            except BaseException:
                Path(temporary).unlink(missing_ok=True)
                raise
        except OSError as exc:
            raise ConfigurationError(
                f"cannot write the known-vaults file at {self.path}: {exc.strerror or exc}. "
                "This client remembers each vault's key so that a changed one is "
                f"refused. Set {ENV_VAR} to a writable path, or pass `pins=`."
            ) from exc

    def get(self, api_base: str, client_id: str, external_id: str) -> str | None:
        entry = self._read().get(_scope(api_base, client_id, external_id))
        return entry.get("fingerprint") if isinstance(entry, dict) else None

    def set(self, api_base: str, client_id: str, external_id: str, fingerprint: str) -> None:
        vaults = self._read()
        vaults[_scope(api_base, client_id, external_id)] = {"fingerprint": fingerprint}
        self._write(vaults)

    def forget(self, api_base: str, client_id: str, external_id: str) -> None:
        vaults = self._read()
        if vaults.pop(_scope(api_base, client_id, external_id), None) is not None:
            self._write(vaults)


__all__ = ["ENV_VAR", "FilePins", "KeyPins", "MemoryPins"]
