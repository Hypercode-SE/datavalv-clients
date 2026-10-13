"""`datavalv` — the operator's side of connecting a server, as three commands.

What `/connect-system` asks of an operator is a keypair made with `openssl`, a
registration in the browser, a JWT minted per call because a token is single
use, and four HTTP calls in one order with an `x-amz-checksum-sha256` header on
the third. Two of those are genuinely irreducible: the keypair has to be made on
the machine that will sign with it, and the registration has to be done by a
signed-in person. The rest is this:

    datavalv keygen                        # a keypair; the public half to paste
    datavalv vault create --external-id …  # one vault, for one customer
    datavalv push dump.sql.gz --external-id …

**Registration is not here and will not be.** `POST /v1/apps` sits on the
Cognito authorizer, so it needs a signed-in account — and a command-line tool
that asked for a Datavalv password would be asking for the one password this
product is built never to see. `keygen` prints the public half; a person pastes
it into `/applications` and gets back the two ids.

Settings come from flags, falling back to the environment:

    DATAVALV_API          https://api.datavalv.se
    DATAVALV_CLIENT_ID    what /applications issued
    DATAVALV_KEY_ID       the kid of the registered signing key
    DATAVALV_PRIVATE_KEY  a PATH to the key file — never the key itself

That last one is a path on purpose. A private key in an environment variable is
in `ps`, in the shell history of whatever set it, and in every crash dump of the
process that read it.

Identifiers go to stdout and everything else to stderr, so
`BACKUP=$(datavalv push …)` holds a backup id and nothing else.
"""

from __future__ import annotations

import argparse
import os
import stat
import sys
from pathlib import Path

import httpx

from . import __version__, crypto
from .client import DatavalvClient
from .errors import ApiError, AuthError, ConfigurationError, DatavalvError, VaultKeyChanged
from .pins import FilePins

#: Exit codes, for a schedule that branches on them.
#:
#: `RETRY` is the one that earns its keep: a vault whose owner has not signed in
#: yet answers `409 tenant_not_initialized`, and a cron job that treats that as
#: a failure pages somebody about a server that is working perfectly. Anything
#: under `RETRY` is worth running again unchanged; anything under `REFUSED` or
#: `CONFIG` needs a person.
EXIT_OK = 0
EXIT_FAILED = 1
EXIT_USAGE = 2  # argparse's own, restated here so the table is complete
EXIT_CONFIG = 3
EXIT_AUTH = 4
EXIT_RETRY = 5
EXIT_REFUSED = 6
#: Neither of its neighbours. 5 would have a schedule push again every night
#: against a key that is wrong every night; 6 says the *service* refused, when
#: this is the client refusing the service. It needs a person, and it needs them
#: to know which thing to go and compare.
EXIT_KEY_CHANGED = 7

DEFAULT_KEY_FILENAME = "datavalv-signing.pem"

#: The four steps, in the one order they work in.
#:
#: A list of commands says what each one does and nothing about which comes
#: first, and three of these are done once ever while the fourth runs nightly.
#: Step 2 is not a command at all -- nothing here can register a key, because
#: registering it is an act of the account that owns the server -- and leaving
#: it out of the list is what makes step 3 fail with `403` for a reader who
#: thought `keygen` had done it.
_ORDER = """getting started, in order:
  1. datavalv keygen                 make the signing keypair; the private
                                     half never leaves this machine
  2. paste the public half into      registering it is what lets the service
     /applications, in the browser   check a signature; no command does this
  3. datavalv vault create           one vault per customer, once each
  4. datavalv push FILE              nightly, from cron or your own scheduler

  Steps 1-3 happen once. Only step 4 repeats."""

_EXIT_TABLE = """exit codes:
  0  done
  1  failed for a reason not covered below
  2  the command line was wrong
  3  a setting, or a file named on the command line, is missing or unusable
  4  the signing key, client id or key id was refused
  5  nothing is wrong; run it again later (vault not started yet, network, quota)
  6  the service refused the request and a person must look at it
  7  the key offered for the vault is not the one on record; nothing was sent"""


# ---------------------------------------------------------------- settings


def _resolve(value: str | None, env_name: str, flag: str, what: str) -> str:
    resolved = value or os.environ.get(env_name) or ""
    if not resolved.strip():
        raise ConfigurationError(f"no {what}: pass {flag} or set {env_name}")
    return resolved.strip()


def _read_private_key(path_text: str) -> str:
    """The signing key's PEM, off disk, complaining about a readable file.

    The mode check is a warning rather than a refusal. A key that others can
    read is a real problem and the operator should be told at the moment they
    are reminded it exists — but refusing to push a backup over a permission bit
    would turn a warning into a missed night's copy, which is the worse of the
    two.

    **The key itself is refused here, and its value is never echoed.** A PEM in
    `DATAVALV_PRIVATE_KEY` is the mistake the variable is a path to prevent, and
    the natural failure — `Path(pem).read_text()` raising, reported with the
    filename in it — would print the operator's private key to stderr and into
    whatever collects their cron output.
    """
    if "-----BEGIN" in path_text:
        raise ConfigurationError(
            "the signing key was given as key text rather than as a path to it. "
            "DATAVALV_PRIVATE_KEY names a file: a private key in an environment "
            "variable is visible in ps, in the shell history that set it and in "
            "any crash dump. Write it to a file with mode 600 and pass the path. "
            "(The value is not repeated here, for the same reason.)"
        )

    path = Path(path_text).expanduser()
    try:
        pem = path.read_text()
    except OSError as exc:
        raise ConfigurationError(
            f"cannot read the signing key at {path}: {exc.strerror or exc}"
        ) from exc

    if "-----BEGIN" not in pem:
        raise ConfigurationError(
            f"{path} does not look like a PEM key. DATAVALV_PRIVATE_KEY is a path "
            "to the key file, not the key."
        )

    mode = path.stat().st_mode
    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        print(
            f"warning: {path} is readable by others (mode {stat.filemode(mode)}); chmod 600 it",
            file=sys.stderr,
        )
    return pem


def _client(args: argparse.Namespace, transport: httpx.BaseTransport | None) -> DatavalvClient:
    api = _resolve(args.api, "DATAVALV_API", "--api", "API address")
    client_id = _resolve(args.client_id, "DATAVALV_CLIENT_ID", "--client-id", "client id")
    key_id = _resolve(args.key_id, "DATAVALV_KEY_ID", "--key-id", "key id")
    key_path = _resolve(args.private_key, "DATAVALV_PRIVATE_KEY", "--private-key", "signing key")
    return DatavalvClient(
        api,
        client_id,
        key_id,
        _read_private_key(key_path),
        transport=transport,
    )


# ---------------------------------------------------------------- commands


def _keygen(args: argparse.Namespace) -> int:
    """An RSA-3072 keypair: the private half to a file only its owner can read,
    the public half to stdout.

    **The private half is never printed and never sent anywhere.** It exists in
    this process only long enough to be written to the file descriptor opened
    below, which is created with mode `0600` before a byte is in it — writing it
    world-readable and then fixing the mode leaves a window in which it is
    readable, and a window is all it takes.
    """
    path = Path(args.out).expanduser()

    if path.exists() and not args.force:
        print(
            f"{path} already exists. Refusing to replace a signing key that may "
            "still be registered — pass --force if that is what you mean, and "
            "retire the old key in /applications afterwards.",
            file=sys.stderr,
        )
        return EXIT_FAILED

    private_key = crypto.generate_keypair()

    try:
        if args.force and path.exists():
            # Unlinked rather than truncated, so the descriptor below is
            # created fresh at 0600. Truncating an existing file keeps whatever
            # mode that file already had, which may be the mode that made
            # replacing the key necessary.
            path.unlink()
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except OSError as exc:
        print(f"cannot write {path}: {exc.strerror or exc}", file=sys.stderr)
        return EXIT_FAILED

    with os.fdopen(fd, "w") as handle:
        handle.write(crypto.private_key_to_pem(private_key))
    # Explicit, because the mode passed to `os.open` is masked by the umask and
    # a umask that clears the owner's write bit would leave a key file its owner
    # cannot rotate. This sets exactly 0600 — it can give the owner their own
    # write bit back, and it grants nothing to group or other under any umask.
    #
    # It is a tidy-up, not the protection: the file was created at 0600 above,
    # so there is no moment at which it exists readable. Deleting this line
    # leaves the key safe; making `os.open` create it at 0644 does not, which is
    # what `test_keygen_creates_the_key_at_0600_rather_than_fixing_it_afterwards`
    # holds apart by neutering this call.
    os.chmod(path, 0o600)

    public_pem = crypto.public_key_to_pem(private_key.public_key())
    print(public_pem, end="" if public_pem.endswith("\n") else "\n")

    print(
        f"\nThe private half is in {path}, mode 600, and must not leave this "
        "machine.\nPaste the block above into /applications in the browser — "
        "sign in first — and\nkeep the two values it answers with:\n"
        "  DATAVALV_CLIENT_ID  identifies this server\n"
        "  DATAVALV_KEY_ID     identifies this key",
        file=sys.stderr,
    )
    return EXIT_OK


def _vault_create(args: argparse.Namespace, transport: httpx.BaseTransport | None) -> int:
    with _client(args, transport) as client:
        vault = client.create_vault(
            args.external_id,
            args.owner_email,
            name=args.name,
            locale=args.locale,
            retention_count=args.retention,
        )

    print(vault.tenant_id)
    print(
        f"Vault {vault.tenant_id} is {vault.status}, and {args.owner_email} has been "
        "emailed.\n"
        "That address is the whole of the connection: the vault appears only to an "
        "account\nwhose confirmed address is identical to it, and a mistyped one is "
        "reported to\nnobody. Until the owner signs in and starts the vault, a push "
        "answers\n409 tenant_not_initialized — which is correct, and exit code 5.",
        file=sys.stderr,
    )
    return EXIT_OK


def _push(args: argparse.Namespace, transport: httpx.BaseTransport | None) -> int:
    data, name = _read_payload(args)

    with _client(args, transport) as client:
        pushed = client.push_backup(
            args.external_id,
            data,
            name=name,
            label=args.label,
            keep=args.keep,
            idempotency_key=args.idempotency_key,
        )

    print(pushed.backup_id)
    print(
        f"{pushed.size} bytes encrypted and stored as {pushed.backup_id}"
        + (f"; {pushed.pruned} older copy(ies) pruned" if pushed.pruned else ""),
        file=sys.stderr,
    )
    if pushed.kept:
        print(
            "This copy is outside retention and will be kept until a member deletes it "
            "or releases it.",
            file=sys.stderr,
        )
    if pushed.key_first_seen:
        # Once, and never again for this vault. A line repeated every night is
        # a line nobody reads, and the night it mattered would look like all
        # the others.
        print(
            f"\nThis is the first copy this machine has pushed to {args.external_id}. "
            "It was encrypted to the key\nthe service offered, whose fingerprint is\n\n"
            f"  {pushed.key_fingerprint}\n\n"
            "That key is now on record here and a different one will be refused. To know "
            "it is the vault's\nand not merely the first one offered, ask the vault's owner "
            "for the fingerprint shown under their backups\n-- it is worked out in their "
            "browser from the key they hold -- and check that it is the same.",
            file=sys.stderr,
        )
    return EXIT_OK


def _vault_delete(args: argparse.Namespace, transport: httpx.BaseTransport | None) -> int:
    with _client(args, transport) as client:
        deleted = client.delete_vault(args.external_id, confirm=args.confirm)

    print(deleted.tenant_id)
    print(
        f"Vault {deleted.tenant_id} ({args.external_id}) is {deleted.status}.\n"
        "Its rows are gone and its copies are being deleted from storage. None of it\n"
        "can be recovered, and the identifier is free for reuse.",
        file=sys.stderr,
    )
    return EXIT_OK


def _vault_retention(args: argparse.Namespace, transport: httpx.BaseTransport | None) -> int:
    with _client(args, transport) as client:
        client.set_retention(args.external_id, args.keep)

    print(args.keep)
    print(
        f"{args.external_id} will keep {args.keep} "
        f"{'kopia' if args.keep == 1 else 'kopior'}.\n"
        "Nothing was deleted by this. Retention runs when the next copy is confirmed,\n"
        "so lowering the number frees nothing until the next push — and a vault that is\n"
        "never pushed to again keeps every copy it has.",
        file=sys.stderr,
    )
    return EXIT_OK


def _vault_key(args: argparse.Namespace, transport: httpx.BaseTransport | None) -> int:
    """Show, trust or forget the key on record for one vault.

    **`--trust` is the strongest first use there is.** The fingerprint the owner
    reads out was worked out in their browser from the private key they hold,
    so a pin made from it never passed through the service -- and a substituted
    key is then refused on the first push, not the second. It and `--forget`
    are local acts: neither makes a request.

    Plain, it prints the fingerprint of the key the service offers *now*, on
    stdout, and records nothing. Looking is not trusting.
    """
    api = _resolve(args.api, "DATAVALV_API", "--api", "API address").rstrip("/")
    api = api.removesuffix("/v1")
    client_id = _resolve(args.client_id, "DATAVALV_CLIENT_ID", "--client-id", "client id")
    pins = FilePins.default()
    scope = (api, client_id, args.external_id)

    if args.forget:
        pins.forget(*scope)
        print(
            f"No key is on record for {args.external_id} any more. The next push records "
            "the one it is offered.",
            file=sys.stderr,
        )
        return EXIT_OK

    if args.trust is not None:
        fingerprint = args.trust.strip().lower().replace(" ", "").replace(":", "")
        if len(fingerprint) != 64 or any(c not in "0123456789abcdef" for c in fingerprint):
            raise ConfigurationError(
                "--trust takes a fingerprint: 64 hexadecimal characters, as shown under "
                "the owner's backups"
            )
        pins.set(*scope, fingerprint)
        print(
            f"{fingerprint} is on record for {args.external_id} in {pins.path}. A push "
            "offered any other key will be refused.",
            file=sys.stderr,
        )
        return EXIT_OK

    with _client(args, transport) as client:
        offered = crypto.public_key_fingerprint(
            client.tenant_public_key(args.external_id)["publicKeyPem"]
        )
    print(offered)

    pinned = pins.get(*scope)
    if pinned is None:
        print(
            "That is the key the service offers now. It is not on record here and this "
            "command does not\nrecord it: compare it with the fingerprint under the "
            "owner's backups, then either push, or\nrecord the owner's with --trust.",
            file=sys.stderr,
        )
        return EXIT_OK
    if pinned == offered:
        print("It matches the key on record for this vault.", file=sys.stderr)
        return EXIT_OK
    print(
        f"It is NOT the key on record for this vault, which is\n  {pinned}\n"
        "A vault's key never changes. Do not push until you know why this one has.",
        file=sys.stderr,
    )
    return EXIT_KEY_CHANGED


def _read_payload(args: argparse.Namespace) -> tuple[bytes, str | None]:
    """The file's bytes and the name to encrypt beside them.

    `-` reads stdin, which is what makes `pg_dump … | datavalv push -` work, and
    it carries no name: there is no filename to encrypt and inventing one would
    put a guess in the vault.
    """
    if args.file == "-":
        return sys.stdin.buffer.read(), None

    path = Path(args.file)
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise ConfigurationError(f"cannot read {path}: {exc.strerror or exc}") from exc

    if args.no_name:
        return data, None
    # The basename. What directory a source server keeps its dumps in is nobody
    # else's business, and the name itself is encrypted under the backup's own
    # key either way.
    return data, args.name_as or path.name


# ---------------------------------------------------------------- argv


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="datavalv",
        description=(
            "Push end-to-end encrypted backups to Datavalv.\n\n"
            "Every copy is encrypted on this machine, against a public key "
            "belonging to\nthe customer's vault, before anything leaves. What "
            "reaches the service is\nciphertext, a size, a digest and a label: "
            "nobody there can read a backup, and\nneither can this program "
            "once it has sealed one."
        ),
        epilog=f"{_ORDER}\n\n{_EXIT_TABLE}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"datavalv {__version__}",
        help="print the version and exit",
    )
    subcommands = parser.add_subparsers(dest="command", required=True)

    # The connection settings, attached to the commands that make requests.
    # `keygen` deliberately has none of them: it talks to nothing, and a
    # keypair made on a machine that cannot reach the API is still a keypair.
    connection = argparse.ArgumentParser(add_help=False)
    connection.add_argument("--api", help="API address [$DATAVALV_API]")
    connection.add_argument("--client-id", help="registered client id [$DATAVALV_CLIENT_ID]")
    connection.add_argument("--key-id", help="registered signing key id [$DATAVALV_KEY_ID]")
    connection.add_argument(
        "--private-key",
        help="path to the signing key PEM [$DATAVALV_PRIVATE_KEY]",
    )

    keygen = subcommands.add_parser(
        "keygen",
        help="make an RSA-3072 signing keypair; print the public half",
        description=(
            "Write an RSA-3072 private key to a file only you can read and print "
            "the\npublic half for pasting into /applications. The private half is "
            "never printed\nand never sent anywhere.\n\n"
            "The file is created at mode 0600 rather than fixed afterwards, so "
            "there is no\nmoment at which it is readable by anybody else."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    keygen.add_argument(
        "--out", default=DEFAULT_KEY_FILENAME, help=f"where to write it [{DEFAULT_KEY_FILENAME}]"
    )
    keygen.add_argument("--force", action="store_true", help="replace an existing key file")

    vault = subcommands.add_parser(
        "vault",
        help="vaults, one per customer",
        description=(
            "One vault per customer, organisation or server whose data you push. "
            "The vault\nis the billed unit and the unit a person owns: its owner "
            "signs in with their\nown account and reads the copies in their own "
            "browser, and you cannot.\n\n"
            "  create      once per customer, when you take them on\n"
            "  retention   how many copies it keeps; changeable at any time\n"
            "  key         the fingerprint of the key your copies are sealed to\n"
            "  delete      end it: rows, copies and identifier, irrecoverably"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    vault_commands = vault.add_subparsers(dest="vault_command", required=True)
    vault_create = vault_commands.add_parser(
        "create",
        parents=[connection],
        help="create a vault and email its owner",
        description=(
            "Create one vault and email the person who will own it.\n\n"
            "--external-id is your own identifier for the customer, and every later "
            "call\nuses it. --owner-email is the whole of the connection between "
            "the vault and\nthe person: there is no invitation link and no code, "
            "and the vault appears\nonly to an account whose *confirmed* address "
            "is identical to the one you send.\n\n"
            "A mistyped --owner-email still returns 201, still sends a mail, and is "
            "never\nreported as an error to anyone -- the owner simply never sees a "
            "vault, and\nyou never find out. Read it back to the customer before "
            "you run this.\n\n"
            "Until the owner signs in and starts the vault, a push answers 409 "
            "and exits 5,\nwhich is correct and means wait."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    vault_create.add_argument("--external-id", required=True, help="your own id for it")
    vault_create.add_argument(
        "--owner-email", required=True, help="the owner's address; read it back first"
    )
    vault_create.add_argument("--name", help="a name for the vault")
    vault_create.add_argument(
        "--locale",
        choices=("sv", "en"),
        help="what language to write the invitation in [sv]",
    )
    vault_create.add_argument("--retention", type=int, help="how many copies to keep [1]")

    vault_delete = vault_commands.add_parser(
        "delete",
        parents=[connection],
        help="end a vault: its rows, its copies and its identifier",
        description=(
            "Delete a vault. Its member rows, its backup rows and its copies in "
            "storage all go, none of it can be recovered, and the identifier is "
            "freed for reuse. --confirm must repeat --external-id: the service asks "
            "for the identifier twice so that one wrong variable cannot end a "
            "customer's vault, and this does not fill the second one in for you."
        ),
    )
    vault_delete.add_argument("--external-id", required=True, help="the vault to end")
    vault_delete.add_argument(
        "--confirm", required=True, help="the same identifier again, typed out"
    )

    vault_retention = vault_commands.add_parser(
        "retention",
        parents=[connection],
        help="change how many copies a vault keeps",
        description=(
            "Set how many copies the vault keeps. Nothing is deleted by this call: "
            "retention runs when the next copy is confirmed, so lowering the number "
            "frees nothing until the next push."
        ),
    )
    vault_retention.add_argument("--external-id", required=True, help="the vault")
    vault_retention.add_argument(
        "--keep", type=int, required=True, help="how many copies to keep, 1-365"
    )

    vault_key = vault_commands.add_parser(
        "key",
        parents=[connection],
        help="show, trust or forget the fingerprint of a vault's key",
        description=(
            "Print the fingerprint of the key the service offers for a vault, and "
            "say\nwhether it is the one on record here.\n\n"
            "The vault's owner sees the same fingerprint under their backups, worked "
            "out\nin their own browser out of the key they hold. Compare the two "
            "before the\nfirst push: they are what tells a real vault from a key "
            "somebody else\nsubstituted. Record theirs with --trust, and every later "
            "push checks against\nit -- a key that changes after that stops the push "
            "rather than sealing a copy\nto it."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    vault_key.add_argument("--external-id", required=True, help="the vault")
    how = vault_key.add_mutually_exclusive_group()
    how.add_argument(
        "--trust",
        metavar="FINGERPRINT",
        help="record this fingerprint, read out by the vault's owner; makes no request",
    )
    how.add_argument(
        "--forget",
        action="store_true",
        help="drop the key on record, after a vault was deleted and created again",
    )

    push = subcommands.add_parser(
        "push",
        parents=[connection],
        help="encrypt a file, upload it and confirm it",
        description=(
            "Encrypt FILE against the vault's public key, upload the ciphertext "
            "and confirm it.\n\n"
            "Four calls, and all of them or none: the copy counts only once the "
            "last one\nhas returned, and until then the previous copy is untouched. "
            "A run that dies\nhalfway leaves the customer with the backup they had, "
            "never with neither.\n\n"
            "What the service can see of a copy: its size, a digest of the "
            "ciphertext, and\n--label if you send one. The filename travels "
            "encrypted with the file, so it\nis readable only to the vault's members "
            "-- --name-as sends a different one and\n--no-name sends none at all. "
            "--label is plaintext and is not; it is for a word\nlike 'nightly', "
            "not for anything about the customer.\n\n"
            "Rerun a failed push with the same --idempotency-key and the night is "
            "stored\nonce rather than twice."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    push.add_argument("file", metavar="FILE", help="the file to push, or - for stdin")
    push.add_argument("--external-id", required=True, help="the vault to push to")
    push.add_argument("--label", help="a plaintext note, visible to members")
    push.add_argument("--name-as", help="send this as the (encrypted) filename instead of FILE's")
    push.add_argument(
        "--no-name",
        action="store_true",
        help="send no filename at all, not even encrypted",
    )
    push.add_argument(
        "--keep",
        action="store_true",
        help="keep this copy until a member deletes it; retention never removes it",
    )
    push.add_argument(
        "--idempotency-key",
        help="send Idempotency-Key, so a retried run does not store the night twice",
    )

    return parser


def _dispatch(args: argparse.Namespace, transport: httpx.BaseTransport | None) -> int:
    if args.command == "keygen":
        return _keygen(args)
    if args.command == "vault":
        if args.vault_command == "key":
            return _vault_key(args, transport)
        if args.vault_command == "retention":
            return _vault_retention(args, transport)
        if args.vault_command == "delete":
            return _vault_delete(args, transport)
        return _vault_create(args, transport)
    if args.command == "push":
        return _push(args, transport)
    raise AssertionError(f"unreachable command {args.command!r}")  # pragma: no cover


def main(argv: list[str] | None = None, *, transport: httpx.BaseTransport | None = None) -> int:
    """Run one command and answer with its exit code.

    `transport` is httpx's own injection seam and exists for the tests, which
    drive the real client against a mock transport rather than a live server.
    Nothing on the command line reaches it.
    """
    args = build_parser().parse_args(argv)

    # Every run says which version it was, on stderr.
    #
    # The one fact nobody includes in a bug report, because nobody thinks of
    # it: both clients publish from a tag and an operator may be several
    # releases behind without knowing. A line in the output of the run that
    # went wrong answers it before it has to be asked.
    #
    # stderr, never stdout. stdout here is read by machines -- the tenant id
    # from `vault create`, the fingerprint from `vault key`, which the README
    # compares in a one-line shell test -- and a banner on it turns every such
    # comparison false.
    print(f"datavalv {__version__}", file=sys.stderr)

    try:
        return _dispatch(args, transport)
    except ConfigurationError as exc:
        print(f"datavalv: {exc}", file=sys.stderr)
        return EXIT_CONFIG
    except AuthError as exc:
        print(f"datavalv: {exc}", file=sys.stderr)
        return EXIT_AUTH
    except VaultKeyChanged as exc:
        print(f"datavalv: {exc}", file=sys.stderr)
        return EXIT_KEY_CHANGED
    except DatavalvError as exc:
        print(f"datavalv: {exc}", file=sys.stderr)
        return EXIT_RETRY if exc.retryable else _refusal_code(exc)
    except ValueError as exc:
        # A field this client checked before sending: an over-long label, a
        # name that will not fit the encrypted-filename field.
        print(f"datavalv: {exc}", file=sys.stderr)
        return EXIT_FAILED
    except KeyboardInterrupt:  # pragma: no cover - needs a signal to provoke
        print("\ndatavalv: interrupted", file=sys.stderr)
        return 130


def _refusal_code(exc: DatavalvError) -> int:
    return EXIT_REFUSED if isinstance(exc, ApiError) else EXIT_FAILED


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
