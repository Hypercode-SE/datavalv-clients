"""`datavalv`, from an operator's side: what it writes, what it prints, and what
it exits with.

Two things are worth more than the rest here. `keygen` must never let the
private half reach stdout, a log or a terminal, and a schedule must be able to
tell "the vault has not been started yet" from "something is broken" without
reading prose — which is what the exit codes are for.
"""

from __future__ import annotations

import argparse
import base64
import io
import stat
from types import SimpleNamespace

import httpx
import pytest
from conftest import API_BASE, BACKUP_ID, CLIENT_ID, EXTERNAL_ID, KEY_ID

from datavalv_client import cli, crypto

PLAINTEXT = b"-- a database dump\n" * 32


@pytest.fixture(autouse=True)
def no_ambient_settings(monkeypatch):
    """The developer's own shell must not decide what these tests test."""
    for name in (
        "DATAVALV_API",
        "DATAVALV_CLIENT_ID",
        "DATAVALV_KEY_ID",
        "DATAVALV_PRIVATE_KEY",
    ):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def key_file(tmp_path, signing_key_pem):
    path = tmp_path / "datavalv-signing.pem"
    path.write_text(signing_key_pem)
    path.chmod(0o600)
    return path


def connection(key_file) -> list[str]:
    return [
        "--api",
        API_BASE,
        "--client-id",
        CLIENT_ID,
        "--key-id",
        KEY_ID,
        "--private-key",
        str(key_file),
    ]


def run(argv, service=None) -> int:
    transport = httpx.MockTransport(service) if service is not None else None
    return cli.main(argv, transport=transport)


# ------------------------------------------------------------------ version


def test_every_run_says_which_version_it_is(key_file, capsys, service):
    """Printed on every run, not only on request.

    A bug report that says "the push failed" is answerable and one that says
    it about an unknown version is not -- and the version somebody is running
    is the one fact nobody thinks to include. Both clients publish from a tag
    and an operator may be several behind without knowing it.
    """
    run(
        [
            "vault",
            "retention",
            "--external-id",
            EXTERNAL_ID,
            "--keep",
            "3",
            *connection(key_file),
        ],
        service,
    )

    assert f"datavalv {cli.__version__}" in capsys.readouterr().err


def test_the_version_never_lands_on_stdout(key_file, capsys, service):
    """stdout is read by machines.

    `[ "$(datavalv vault key --external-id x)" = "$FROM_THE_OWNER" ]` is a
    one-line check the README recommends, and a version banner on stdout turns
    every such comparison false. The line goes to stderr with the rest of the
    advisory output.
    """
    run(
        [
            "vault",
            "retention",
            "--external-id",
            EXTERNAL_ID,
            "--keep",
            "3",
            *connection(key_file),
        ],
        service,
    )

    said = capsys.readouterr()
    assert said.out.strip() == "3"
    assert cli.__version__ not in said.out


def test_version_asked_for_on_its_own_goes_to_stdout(capsys):
    """Asked for, so it is the answer rather than a note beside one."""
    with pytest.raises(SystemExit) as raised:
        run(["--version"])

    assert raised.value.code == 0
    assert capsys.readouterr().out.strip().endswith(cli.__version__)


# --------------------------------------------------------------------- help


def _every_parser() -> list[tuple[str, argparse.ArgumentParser]]:
    """(name, parser) for the top-level parser and every command under it."""
    found: list[tuple[str, argparse.ArgumentParser]] = []

    def walk(name: str, parser: argparse.ArgumentParser) -> None:
        found.append((name, parser))
        for action in parser._actions:
            if isinstance(action, argparse._SubParsersAction):
                for child, sub in action.choices.items():
                    walk(f"{name} {child}".strip(), sub)

    walk("datavalv", cli.build_parser())
    return found


def test_every_command_says_what_it_does_before_listing_its_flags():
    """`--help` with nothing but an option list is a screen that answers "what
    are the flags" to somebody who asked "what does this do".

    `vault create` shipped exactly like that: the command with the costliest
    mistake in the product had no prose at all, and the warning about it was
    printed on stderr *after* the call had already gone out.
    """
    missing = [name for name, parser in _every_parser() if not (parser.description or "").strip()]
    assert missing == []


def test_every_command_help_is_more_than_a_sentence():
    """A description is not a restatement of the `help=` line.

    The guard under the guard: `description="create a vault"` would satisfy the
    test above while telling a reader nothing the command list did not.
    """
    thin = [
        (name, len((parser.description or "").split()))
        for name, parser in _every_parser()
        if len((parser.description or "").split()) < 15
    ]
    assert thin == []


def test_vault_create_help_names_the_mistake_it_cannot_catch():
    """The one thing a reader has to know *before* running this command.

    A mistyped `--owner-email` returns 201, mails somebody who will never read
    it, and is reported as an error to nobody. Saying so afterwards, which is
    what the success message does, is saying it to somebody who has already
    made the mistake.
    """
    help_text = " ".join(dict(_every_parser())["datavalv vault create"].description.split())

    assert "--owner-email" in help_text
    # That it succeeds is the surprising half; a reader who thinks a typo will
    # be refused has no reason to read it back.
    assert "read it back" in help_text.lower()


def test_the_top_level_help_says_what_order_to_do_things_in():
    """A command list is not a procedure.

    Four of these have to happen in one order, once, before any backup can be
    pushed -- and nothing on the screen said so, which left `/connect-system`
    and the README as the only places that did.
    """
    epilog = " ".join((cli.build_parser().epilog or "").split())

    for step in ["keygen", "vault create", "push"]:
        assert step in epilog
    # The registration between the first two: the public half has to reach
    # /applications, and no command here can do it.
    assert "/applications" in epilog


# ------------------------------------------------------------------- keygen


def test_keygen_writes_a_private_key_only_its_owner_can_read(tmp_path, capsys):
    out = tmp_path / "signing.pem"
    assert run(["keygen", "--out", str(out)]) == cli.EXIT_OK

    mode = stat.S_IMODE(out.stat().st_mode)
    assert mode == 0o600, f"mode is {oct(mode)}; a signing key must not be readable by others"
    assert "PRIVATE KEY" in out.read_text()


def test_keygen_creates_the_key_at_0600_rather_than_fixing_it_afterwards(tmp_path, monkeypatch):
    """The file must never exist readable, not merely end up unreadable.

    The test above passes for a `keygen` that creates the file world-readable
    and chmods it a moment later — and that moment is the whole vulnerability:
    anything watching the directory wins the race and has the key. So here the
    `chmod` is neutered and the umask opened right up, which leaves the mode
    passed to `os.open` as the only thing that can produce 0600.
    """
    monkeypatch.setattr(cli.os, "chmod", lambda *args, **kwargs: None)
    previous = cli.os.umask(0o000)
    try:
        out = tmp_path / "signing.pem"
        assert run(["keygen", "--out", str(out)]) == cli.EXIT_OK
        assert stat.S_IMODE(out.stat().st_mode) == 0o600
    finally:
        cli.os.umask(previous)


def test_keygen_never_prints_the_private_half(tmp_path, capsys):
    """The one output this command must not produce.

    Probed by making `_keygen` print `private_key_to_pem(...)` instead of the
    public half: this fails, and so does the test below, which is the pair that
    makes "prints something" and "prints the right thing" separate questions.
    """
    out = tmp_path / "signing.pem"
    run(["keygen", "--out", str(out)])
    captured = capsys.readouterr()

    for stream in (captured.out, captured.err):
        assert "PRIVATE KEY" not in stream
        assert "-----BEGIN RSA" not in stream
    # Not a single line of the key file, either: a key printed in pieces is
    # still a key printed.
    body = [line for line in out.read_text().splitlines() if "-----" not in line]
    assert body, "the key file should have content"
    for line in body:
        assert line not in captured.out
        assert line not in captured.err


def test_keygen_prints_the_public_half_of_the_key_it_wrote(tmp_path, capsys):
    out = tmp_path / "signing.pem"
    run(["keygen", "--out", str(out)])
    printed = capsys.readouterr().out

    on_disk = crypto.load_private_key_pem(out.read_text())
    assert printed.strip() == crypto.public_key_to_pem(on_disk.public_key()).strip()
    assert on_disk.key_size == 3072


def test_keygen_refuses_to_replace_an_existing_key(tmp_path, capsys):
    """A key file that is already registered is not something to overwrite by
    accident: the replacement signs nothing the service will accept."""
    out = tmp_path / "signing.pem"
    out.write_text("existing\n")

    assert run(["keygen", "--out", str(out)]) == cli.EXIT_FAILED
    assert out.read_text() == "existing\n"
    assert "--force" in capsys.readouterr().err


def test_keygen_force_replaces_it_and_still_writes_0600(tmp_path):
    out = tmp_path / "signing.pem"
    out.write_text("existing\n")
    out.chmod(0o644)

    assert run(["keygen", "--out", str(out), "--force"]) == cli.EXIT_OK
    assert "PRIVATE KEY" in out.read_text()
    assert stat.S_IMODE(out.stat().st_mode) == 0o600


# ------------------------------------------------------------------ settings


@pytest.mark.parametrize(
    ("drop", "env_name", "flag"),
    [
        ("--api", "DATAVALV_API", "--api"),
        ("--client-id", "DATAVALV_CLIENT_ID", "--client-id"),
        ("--key-id", "DATAVALV_KEY_ID", "--key-id"),
        ("--private-key", "DATAVALV_PRIVATE_KEY", "--private-key"),
    ],
)
def test_a_missing_setting_names_the_flag_and_the_variable(
    tmp_path, key_file, capsys, service, drop, env_name, flag
):
    argv = connection(key_file)
    index = argv.index(drop)
    del argv[index : index + 2]

    code = run(["push", str(_dump(tmp_path)), "--external-id", EXTERNAL_ID, *argv], service)

    assert code == cli.EXIT_CONFIG
    message = capsys.readouterr().err
    assert flag in message
    assert env_name in message
    assert service.calls == [], "nothing should be sent before the settings are complete"


def test_settings_fall_back_to_the_environment(tmp_path, key_file, monkeypatch, service):
    monkeypatch.setenv("DATAVALV_API", API_BASE)
    monkeypatch.setenv("DATAVALV_CLIENT_ID", CLIENT_ID)
    monkeypatch.setenv("DATAVALV_KEY_ID", KEY_ID)
    monkeypatch.setenv("DATAVALV_PRIVATE_KEY", str(key_file))

    code = run(["push", str(_dump(tmp_path)), "--external-id", EXTERNAL_ID], service)

    assert code == cli.EXIT_OK
    assert len(service.calls) == 4


def test_the_key_itself_in_the_environment_is_refused_and_not_echoed(
    tmp_path, monkeypatch, capsys, signing_key_pem, service
):
    """`DATAVALV_PRIVATE_KEY` is a path, and the failure must not print the key.

    Letting `Path(pem).read_text()` fail naturally would report the filename it
    could not open — which is the operator's private key, on stderr and into
    whatever collects their cron output.
    """
    monkeypatch.setenv("DATAVALV_API", API_BASE)
    monkeypatch.setenv("DATAVALV_CLIENT_ID", CLIENT_ID)
    monkeypatch.setenv("DATAVALV_KEY_ID", KEY_ID)
    monkeypatch.setenv("DATAVALV_PRIVATE_KEY", signing_key_pem)

    code = run(["push", str(_dump(tmp_path)), "--external-id", EXTERNAL_ID], service)

    assert code == cli.EXIT_CONFIG
    captured = capsys.readouterr()
    for line in signing_key_pem.splitlines():
        if "-----" not in line and line.strip():
            assert line not in captured.err
            assert line not in captured.out
    assert "path" in captured.err


def test_a_world_readable_key_warns_but_still_works(tmp_path, key_file, capsys, service):
    """A permission bit must not cost a night's backup — but must be said."""
    key_file.chmod(0o644)

    code = run(
        ["push", str(_dump(tmp_path)), "--external-id", EXTERNAL_ID, *connection(key_file)],
        service,
    )

    assert code == cli.EXIT_OK
    assert "readable by others" in capsys.readouterr().err


# ---------------------------------------------------------------------- push


def _dump(tmp_path) -> object:
    path = tmp_path / "dump.sql.gz"
    path.write_bytes(PLAINTEXT)
    return path


def test_push_prints_the_backup_id_and_nothing_else_on_stdout(tmp_path, key_file, capsys, service):
    """`BACKUP=$(datavalv push …)` has to hold an id, not a paragraph."""
    code = run(
        ["push", str(_dump(tmp_path)), "--external-id", EXTERNAL_ID, *connection(key_file)],
        service,
    )

    assert code == cli.EXIT_OK
    captured = capsys.readouterr()
    assert captured.out.strip() == BACKUP_ID
    assert len(service.calls) == 4


def test_push_encrypts_the_basename_and_not_the_path(tmp_path, key_file, service, tenant_key):
    """The name that travels is `dump.sql.gz`, encrypted — never the directory.

    Opened here with the tenant key, the way a member's browser will: asserting
    only that the field is present passes for a client that sends the whole
    absolute path, which tells a reader where this server keeps its dumps.
    """
    dump = _dump(tmp_path)
    run(
        ["push", str(dump), "--external-id", EXTERNAL_ID, *connection(key_file)],
        service,
    )

    body = service.calls[1].json()
    dek = crypto.unwrap_dek(base64.b64decode(body["wrappedDekB64"]), tenant_key)
    name = crypto.decrypt(base64.b64decode(body["nameCipherB64"]), dek)
    assert name == b"dump.sql.gz"
    assert str(tmp_path).encode() not in name


def test_push_sends_the_name_it_was_told_to_send(tmp_path, key_file, service, tenant_key):
    """`--name-as`, for a dump written to a temporary file with a useless name."""
    run(
        [
            "push",
            str(_dump(tmp_path)),
            "--external-id",
            EXTERNAL_ID,
            "--name-as",
            "medlemsregister-2026-09-17.sql.gz",
            *connection(key_file),
        ],
        service,
    )

    body = service.calls[1].json()
    dek = crypto.unwrap_dek(base64.b64decode(body["wrappedDekB64"]), tenant_key)
    assert (
        crypto.decrypt(base64.b64decode(body["nameCipherB64"]), dek)
        == b"medlemsregister-2026-09-17.sql.gz"
    )


def test_push_sends_no_name_when_told_not_to(tmp_path, key_file, service):
    run(
        [
            "push",
            str(_dump(tmp_path)),
            "--external-id",
            EXTERNAL_ID,
            "--no-name",
            *connection(key_file),
        ],
        service,
    )
    assert "nameCipherB64" not in service.calls[1].json()


def test_push_reads_stdin_and_sends_no_name(key_file, monkeypatch, service, capsys):
    """`pg_dump … | datavalv push -` — and no filename to invent."""
    monkeypatch.setattr(cli.sys, "stdin", SimpleNamespace(buffer=io.BytesIO(PLAINTEXT)))

    code = run(["push", "-", "--external-id", EXTERNAL_ID, *connection(key_file)], service)

    assert code == cli.EXIT_OK
    assert "nameCipherB64" not in service.calls[1].json()


def test_push_passes_the_label_and_the_idempotency_key(tmp_path, key_file, service):
    run(
        [
            "push",
            str(_dump(tmp_path)),
            "--external-id",
            EXTERNAL_ID,
            "--label",
            "nattlig",
            "--idempotency-key",
            "2026-09-17",
            *connection(key_file),
        ],
        service,
    )
    assert service.calls[1].json()["label"] == "nattlig"
    assert service.calls[1].headers["Idempotency-Key"] == "2026-09-17"


def test_a_missing_file_is_a_configuration_exit_not_a_traceback(
    tmp_path, key_file, capsys, service
):
    code = run(
        [
            "push",
            str(tmp_path / "nothing-here.sql.gz"),
            "--external-id",
            EXTERNAL_ID,
            *connection(key_file),
        ],
        service,
    )

    assert code == cli.EXIT_CONFIG
    assert "nothing-here.sql.gz" in capsys.readouterr().err


# --------------------------------------------------------------- exit codes


def test_an_unstarted_vault_exits_5_and_says_to_wait(tmp_path, key_file, capsys, service):
    """The code a nightly schedule branches on.

    5 rather than 1 is the whole point: `tenant_not_initialized` means nobody
    has signed in yet, and a job that treats it as a fault sends somebody
    looking for a broken server.
    """
    service.fail_at = f"GET /v1/tenants/{EXTERNAL_ID}/public-key"
    service.failure = (409, b'{"code":"tenant_not_initialized"}')

    code = run(
        ["push", str(_dump(tmp_path)), "--external-id", EXTERNAL_ID, *connection(key_file)],
        service,
    )

    assert code == cli.EXIT_RETRY
    error = capsys.readouterr().err
    assert "Nobody has started this vault yet" in error
    assert "step 1 of 4" in error


def test_a_refused_key_exits_4(tmp_path, key_file, capsys, service):
    service.fail_at = f"GET /v1/tenants/{EXTERNAL_ID}/public-key"
    service.failure = (403, b'{"message":"Forbidden"}')

    code = run(
        ["push", str(_dump(tmp_path)), "--external-id", EXTERNAL_ID, *connection(key_file)],
        service,
    )

    assert code == cli.EXIT_AUTH
    assert "/applications" in capsys.readouterr().err


def test_another_refusal_exits_6(tmp_path, key_file, capsys, service):
    service.fail_at = f"POST /v1/tenants/{EXTERNAL_ID}/backups"
    service.failure = (413, b'{"code":"too_large","detail":"600000000 bytes exceeds"}')

    code = run(
        ["push", str(_dump(tmp_path)), "--external-id", EXTERNAL_ID, *connection(key_file)],
        service,
    )

    assert code == cli.EXIT_REFUSED
    assert "too_large" in capsys.readouterr().err


def test_the_four_exit_codes_are_distinct():
    """They are a branchable surface; two of them being equal is a silent bug."""
    codes = [
        cli.EXIT_OK,
        cli.EXIT_FAILED,
        cli.EXIT_USAGE,
        cli.EXIT_CONFIG,
        cli.EXIT_AUTH,
        cli.EXIT_RETRY,
        cli.EXIT_REFUSED,
        cli.EXIT_KEY_CHANGED,
    ]
    assert len(set(codes)) == len(codes)


def test_no_command_is_a_usage_error(capsys):
    with pytest.raises(SystemExit) as raised:
        cli.main([])
    assert raised.value.code == cli.EXIT_USAGE


# -------------------------------------------------------------- vault delete


def test_vault_delete_sends_the_confirmation_and_says_what_went(key_file, capsys, service):
    code = run(
        [
            "vault",
            "delete",
            "--external-id",
            EXTERNAL_ID,
            "--confirm",
            EXTERNAL_ID,
            *connection(key_file),
        ],
        service,
    )

    assert code == cli.EXIT_OK
    call = service.calls[0]
    assert call.method == "DELETE"
    assert call.json() == {"confirm": EXTERNAL_ID}
    said = capsys.readouterr()
    assert "t-1" in said.out
    # What is gone, said plainly: the copies, not merely the vault row.
    assert "kopior" in said.err or "copies" in said.err


def test_vault_delete_refuses_a_confirmation_that_does_not_match(key_file, capsys, service):
    """The whole point of the flag, and the reason it is not optional.

    An operator who types the wrong identifier into one of the two flags gets
    a refusal and no request. Deriving `--confirm` from `--external-id` would
    make this test impossible to write.
    """
    code = run(
        [
            "vault",
            "delete",
            "--external-id",
            EXTERNAL_ID,
            "--confirm",
            "kund-4712",
            *connection(key_file),
        ],
        service,
    )

    assert code == cli.EXIT_CONFIG
    assert service.calls == []
    assert "confirm" in capsys.readouterr().err


def test_vault_delete_requires_the_confirmation_at_all(key_file, capsys, service):
    with pytest.raises(SystemExit):
        run(
            ["vault", "delete", "--external-id", EXTERNAL_ID, *connection(key_file)],
            service,
        )

    assert service.calls == []


# -------------------------------------------------------------- vault create


def test_vault_create_prints_the_tenant_id_and_sends_the_body(key_file, capsys, service):
    code = run(
        [
            "vault",
            "create",
            "--external-id",
            EXTERNAL_ID,
            "--owner-email",
            "anna@example.se",
            "--name",
            "Kund 4711",
            "--locale",
            "en",
            "--retention",
            "7",
            *connection(key_file),
        ],
        service,
    )

    assert code == cli.EXIT_OK
    assert capsys.readouterr().out.strip() == "t-1"
    assert service.calls[0].json() == {
        "externalId": EXTERNAL_ID,
        "ownerEmail": "anna@example.se",
        "name": "Kund 4711",
        "locale": "en",
        "retentionCount": 7,
    }


def test_vault_create_omits_what_was_not_asked_for(key_file, service):
    run(
        [
            "vault",
            "create",
            "--external-id",
            EXTERNAL_ID,
            "--owner-email",
            "anna@example.se",
            *connection(key_file),
        ],
        service,
    )
    assert service.calls[0].json() == {
        "externalId": EXTERNAL_ID,
        "ownerEmail": "anna@example.se",
    }


# ----------------------------------------------------------- vault retention


def test_vault_retention_patches_and_says_when_it_takes_effect(key_file, capsys, service):
    """The number is easy; *when* it applies is the part an operator gets wrong.

    Nothing is deleted by this call. Retention runs when the next copy is
    confirmed, so a vault that is never pushed to again keeps every copy it
    has -- and an operator who lowered the number to free space and saw
    nothing happen deserves to read why here rather than work it out.
    """
    code = run(
        [
            "vault",
            "retention",
            "--external-id",
            EXTERNAL_ID,
            "--keep",
            "12",
            *connection(key_file),
        ],
        service,
    )

    assert code == cli.EXIT_OK
    call = service.calls[0]
    assert call.method == "PATCH"
    assert call.url.path == f"/v1/tenants/{EXTERNAL_ID}"
    assert call.json() == {"retentionCount": 12}

    said = capsys.readouterr()
    assert "12" in said.out
    # The two halves of what happens next, in the operator's own words.
    assert "nästa" in said.err.lower() or "next" in said.err.lower()


def test_vault_retention_refuses_a_count_out_of_range_without_calling(key_file, capsys, service):
    code = run(
        [
            "vault",
            "retention",
            "--external-id",
            EXTERNAL_ID,
            "--keep",
            "0",
            *connection(key_file),
        ],
        service,
    )

    assert code == cli.EXIT_CONFIG
    assert service.calls == []
    assert "1" in capsys.readouterr().err


def test_vault_create_warns_about_the_address_and_the_wait(key_file, capsys, service):
    """The one mistake `/connect-system` exists to prevent, said where it is made.

    A mistyped `ownerEmail` succeeds, mails nobody who will read it, and is
    reported as an error to no one.
    """
    run(
        [
            "vault",
            "create",
            "--external-id",
            EXTERNAL_ID,
            "--owner-email",
            "anna@example.se",
            *connection(key_file),
        ],
        service,
    )
    error = capsys.readouterr().err
    assert "anna@example.se" in error
    assert "tenant_not_initialized" in error


def test_an_unknown_locale_is_refused_by_the_command_line(key_file):
    """`sv` and `en` are what the service composes in; a third is a 422.

    Caught here rather than sent, because argparse can name the choices and the
    API's answer is `invalid_request` with no field in it.
    """
    with pytest.raises(SystemExit) as raised:
        cli.main(
            [
                "vault",
                "create",
                "--external-id",
                EXTERNAL_ID,
                "--owner-email",
                "anna@example.se",
                "--locale",
                "de",
                *connection(key_file),
            ]
        )
    assert raised.value.code == cli.EXIT_USAGE


# ------------------------------------------------------ the vault's own key


def _pushed(tmp_path, key_file, service) -> int:
    dump = tmp_path / "dump.sql.gz"
    dump.write_bytes(PLAINTEXT)
    return run(["push", str(dump), "--external-id", EXTERNAL_ID, *connection(key_file)], service)


def test_the_first_push_to_a_vault_says_which_key_it_trusted_and_how_to_check(
    tmp_path, key_file, service, tenant_public_pem, capsys
):
    """The one moment the fingerprint is worth a person's attention. After it,
    a push says nothing about keys at all -- a line repeated every night is a
    line nobody reads, and the night it matters would look like every other."""
    assert _pushed(tmp_path, key_file, service) == cli.EXIT_OK
    first = capsys.readouterr()
    assert _pushed(tmp_path, key_file, service) == cli.EXIT_OK
    second = capsys.readouterr()

    fingerprint = crypto.public_key_fingerprint(tenant_public_pem)
    assert first.out.strip() == BACKUP_ID, "stdout carries the backup id and nothing else"
    assert fingerprint in first.err
    assert "under their backups" in first.err
    assert fingerprint not in second.err


def test_a_changed_key_exits_7_sends_nothing_and_prints_no_backup_id(
    tmp_path, key_file, service, capsys
):
    """Its own code, because it is neither of the neighbours: 5 would have a
    schedule try again every night against a key that is wrong every night, and
    6 says the *service* refused, when it is this client refusing the service."""
    assert _pushed(tmp_path, key_file, service) == cli.EXIT_OK
    capsys.readouterr()
    service.tenant_public_pem = crypto.public_key_to_pem(crypto.generate_keypair().public_key())
    service.uploaded = None

    assert _pushed(tmp_path, key_file, service) == cli.EXIT_KEY_CHANGED == 7

    captured = capsys.readouterr()
    assert captured.out == ""
    assert service.uploaded is None
    assert "Nothing was encrypted or sent" in captured.err
    assert "vault key" in captured.err and "--forget" in captured.err


def _vault_key(key_file, service, *extra: str) -> int:
    return run(
        ["vault", "key", "--external-id", EXTERNAL_ID, *extra, *connection(key_file)], service
    )


def test_vault_key_prints_the_fingerprint_and_records_nothing(
    key_file, service, tenant_public_pem, capsys
):
    """Looking is not trusting. The fingerprint goes to stdout so that
    `[ "$(datavalv vault key …)" = "$FROM_THE_OWNER" ]` is a one-line check."""
    assert _vault_key(key_file, service) == cli.EXIT_OK
    captured = capsys.readouterr()

    assert captured.out.strip() == crypto.public_key_fingerprint(tenant_public_pem)
    assert "not on record" in captured.err
    assert _vault_key(key_file, service) == cli.EXIT_OK
    assert "not on record" in capsys.readouterr().err


def test_vault_key_trust_records_the_owners_fingerprint_without_asking_the_service(
    tmp_path, key_file, service, tenant_public_pem, capsys
):
    """**The strongest first use there is.** The fingerprint the owner reads out
    was worked out in their browser from the private key they hold, so a pin
    made from it never passed through the service at all -- and a substituted
    key is then refused on the very first push, not the second."""
    fingerprint = crypto.public_key_fingerprint(tenant_public_pem)
    assert _vault_key(key_file, service, "--trust", fingerprint.upper()) == cli.EXIT_OK
    assert service.calls == [], "trusting a fingerprint is a local act"
    capsys.readouterr()

    assert _pushed(tmp_path, key_file, service) == cli.EXIT_OK
    # Not a first sighting: the key was already on record, put there by a
    # person, so the push has nothing to announce.
    assert fingerprint not in capsys.readouterr().err

    service.tenant_public_pem = crypto.public_key_to_pem(crypto.generate_keypair().public_key())
    assert _pushed(tmp_path, key_file, service) == cli.EXIT_KEY_CHANGED


def test_a_substituted_key_is_refused_on_the_first_push_when_the_owners_was_trusted(
    tmp_path, key_file, service, capsys
):
    assert _vault_key(key_file, service, "--trust", "ab" * 32) == cli.EXIT_OK
    assert _pushed(tmp_path, key_file, service) == cli.EXIT_KEY_CHANGED
    assert service.uploaded is None


def test_vault_key_trust_refuses_something_that_is_not_a_fingerprint(key_file, service, capsys):
    assert _vault_key(key_file, service, "--trust", "de6272b8") == cli.EXIT_CONFIG
    assert "64" in capsys.readouterr().err


def test_vault_key_says_when_the_offered_key_is_not_the_one_on_record(
    tmp_path, key_file, service, capsys
):
    assert _pushed(tmp_path, key_file, service) == cli.EXIT_OK
    assert _vault_key(key_file, service) == cli.EXIT_OK
    assert "matches" in capsys.readouterr().err

    service.tenant_public_pem = crypto.public_key_to_pem(crypto.generate_keypair().public_key())
    assert _vault_key(key_file, service) == cli.EXIT_KEY_CHANGED
    assert "NOT the key on record" in capsys.readouterr().err


def test_vault_key_forget_lets_a_recreated_vault_be_pinned_again(
    tmp_path, key_file, service, capsys
):
    assert _pushed(tmp_path, key_file, service) == cli.EXIT_OK
    service.tenant_public_pem = crypto.public_key_to_pem(crypto.generate_keypair().public_key())
    assert _pushed(tmp_path, key_file, service) == cli.EXIT_KEY_CHANGED

    service.calls.clear()
    assert _vault_key(key_file, service, "--forget") == cli.EXIT_OK
    assert service.calls == [], "forgetting is a local act too"
    assert _pushed(tmp_path, key_file, service) == cli.EXIT_OK


def test_push_keep_asks_for_the_copy_to_outlive_retention(tmp_path, key_file, service, capsys):
    code = run(
        [
            "push",
            str(_dump(tmp_path)),
            "--external-id",
            EXTERNAL_ID,
            "--keep",
            *connection(key_file),
        ],
        service,
    )

    assert code == cli.EXIT_OK
    assert service.calls[1].json()["keep"] is True
    captured = capsys.readouterr()
    assert captured.out.strip() == BACKUP_ID
    assert "kept until a member deletes it" in captured.err
