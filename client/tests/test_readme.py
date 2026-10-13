"""`README.md` as executable documentation.

The README is the answer to "how do I connect a server", and it is the reason
somebody installs this package at all. It is also prose: nothing compiles it,
and the first person to find out that a flag was renamed is an operator whose
copied-and-pasted command exited 2 at three in the morning.

So the document is the source and this file is the only copy. Every `datavalv`
command in it is pulled out of the markdown and handed to the real parser,
every environment variable it names is proved to be one the CLI actually reads,
and its exit-code table is compared against the one the CLI prints. The pattern
is `api/tests/test_runbook_shell_blocks.py`, which does the same for the
runbooks' shell blocks.

None of this checks that the *prose* is true. Nothing can. It checks the parts
that rot silently, which are the parts a reader types.
"""

from __future__ import annotations

import argparse
import ast
import dataclasses
import re
import shlex
from pathlib import Path

import pytest

import datavalv_client
from datavalv_client import cli, pins

CLIENT = Path(__file__).resolve().parents[1]
README = CLIENT / "README.md"
RELEASING = CLIENT / "RELEASING.md"


@pytest.fixture(scope="module")
def readme() -> str:
    return README.read_text()


def _code_blocks(text: str) -> list[str]:
    """Every fenced block, whatever its language tag."""
    return re.findall(r"^```[a-z]*\n(.*?)^```", text, flags=re.MULTILINE | re.DOTALL)


def _datavalv_commands(text: str) -> list[tuple[str, list[str]]]:
    """`(line, argv)` for every `datavalv ...` invocation in a code block.

    The last segment of a pipeline is taken, which is what makes the
    `pg_dump ... | datavalv push -` example in step 6 a real assertion rather
    than a line this parser skips.
    """
    found = []
    for block in _code_blocks(text):
        for line in block.splitlines():
            command = line.split("|")[-1].strip()
            if not command.startswith("datavalv "):
                continue
            found.append((command, shlex.split(command)[1:]))
    return found


def _subcommand_names() -> set[str]:
    """Every command the CLI answers to, a nested one spelled as two words.

    Top-level names alone were not enough: `vault` has subcommands of its
    own, so a new `vault retention` could be added with no line in the README
    and this would still have matched `{keygen, vault, push}` exactly. The
    TypeScript client's own README test compares the full names, and these two
    documents make the same promise about the same commands.
    """
    for action in cli.build_parser()._actions:
        if isinstance(action, argparse._SubParsersAction):
            names = set()
            for name, subparser in action.choices.items():
                nested = [
                    inner
                    for inner in subparser._actions
                    if isinstance(inner, argparse._SubParsersAction)
                ]
                if nested:
                    names.update(f"{name} {child}" for child in nested[0].choices)
                else:
                    names.add(name)
            return names
    raise AssertionError("the parser has no subcommands")  # pragma: no cover


# ------------------------------------------------------------------ commands


def test_the_readme_shows_commands_at_all(readme: str):
    """The guard under the guard: a README that stopped containing commands
    would make every test below pass by having nothing to check."""
    commands = _datavalv_commands(readme)
    assert len(commands) >= 3, [line for line, _ in commands]


def test_every_command_in_the_readme_parses(readme: str):
    parser = cli.build_parser()
    for line, argv in _datavalv_commands(readme):
        try:
            parser.parse_args(argv)
        except SystemExit as exit_:  # argparse's own reporting, turned into a name
            pytest.fail(f"README command does not parse (argparse exit {exit_.code}): {line}")


def test_the_readme_shows_every_command_the_cli_has(readme: str):
    """A command added without a line in the README is a command nobody finds."""
    documented = {
        f"{argv[0]} {argv[1]}" if argv[0] == "vault" and len(argv) > 1 else argv[0]
        for _, argv in _datavalv_commands(readme)
        if argv
    }
    assert documented == _subcommand_names()


def test_the_releasing_commands_name_the_version_being_released():
    """Every version inside a command block in `RELEASING.md` is this one.

    The defect it catches shipped and sat there through two releases: the
    build, inspect and tag commands all still said `0.1.0`, a version that was
    never published, because nobody bumping a release thinks to reread the
    file telling them how to bump a release. Copying any of them does the
    wrong thing quietly -- `tar -tzf` on a tarball that is not there, a tag
    that publishes a version the repository does not declare.

    Prose is exempt on purpose. "0.5.1 took about five minutes to appear" is a
    record of what happened, and a record that rewrote itself every release
    would be worth nothing.
    """
    version = datavalv_client.__version__

    stale = {
        found
        for block in _code_blocks(RELEASING.read_text())
        for found in re.findall(r"\b\d+\.\d+\.\d+\b", block)
        if found != version
    }
    assert stale == set(), f"RELEASING.md commands name {sorted(stale)}, not {version}"


def test_the_readme_uses_the_current_wheel_name(readme: str):
    """The install line names a file. A version bump that misses it leaves a
    command that fails for everyone who copies it."""
    from datavalv_client import __version__

    filenames = re.findall(r"datavalv_client-([0-9][^-]*)-py3-none-any\.whl", readme)
    assert filenames, "the README no longer shows a wheel to install"
    assert set(filenames) == {__version__}


# ------------------------------------------------------------------- library


def _python_blocks(text: str) -> list[str]:
    return re.findall(r"^```python\n(.*?)^```", text, flags=re.MULTILINE | re.DOTALL)


def test_the_readme_sends_nobody_to_a_repository_they_cannot_open(readme: str):
    """`Hypercode-SE/datavalv` is the private monorepo.

    This file is published to PyPI, where every reader is outside the
    organisation, so a `git clone` of the monorepo fails for all of them. The
    public mirror `datavalv-clients` is the one to point at, and the negative
    lookahead below lets exactly that through.

    The symmetric guard lives in `client-ts/tests/readme.test.ts`, because the
    two packages are read in the same place by the same people and a link that
    rots in one will rot in the other.
    """
    private = re.findall(r"github\.com/Hypercode-SE/datavalv(?![-\w])", readme)

    assert not private, (
        "the README points at the private monorepo, which 404s for every reader "
        "on PyPI; the public mirror is Hypercode-SE/datavalv-clients"
    )
    # The positive control: this scan is worth nothing if the README names no
    # repository at all, which is also what a future edit that removed the
    # source link would leave behind.
    assert "github.com/Hypercode-SE/datavalv-clients" in readme, (
        "the README no longer says where the source is"
    )


def test_the_python_examples_are_python(readme: str):
    blocks = _python_blocks(readme)
    assert blocks, "the README no longer shows the library"
    for block in blocks:
        compile(block, str(README), "exec")


def test_the_python_examples_name_things_that_exist(readme: str):
    """Imports, methods and result fields, checked against the real objects.

    The examples cannot simply be run — they would need a signing key and a
    server — so what is checkable is every name they tell a reader to type. A
    renamed method in a README is a copied snippet that raises `AttributeError`
    in somebody's cron job.
    """
    import datavalv_client
    from datavalv_client import CreatedVault, DatavalvClient, DatavalvError, PushedBackup

    imported = set()
    for block in _python_blocks(readme):
        for node in ast.walk(ast.parse(block)):
            if isinstance(node, ast.ImportFrom) and (node.module or "").startswith(
                "datavalv_client"
            ):
                imported.update(alias.name for alias in node.names)
    assert imported, "the README imports nothing from datavalv_client"
    for name in imported:
        assert hasattr(datavalv_client, name), f"the README imports {name}, which is not exported"

    # Inline spans count, not only fenced blocks: `client.list_backups(...)` is
    # documented in a sentence, and rots exactly as fast.
    owners = {
        "client": DatavalvClient,
        "pushed": PushedBackup,
        "vault": CreatedVault,
        "exc": DatavalvError,
    }
    seen = 0
    for variable, owner in owners.items():
        # `dir()` alone is not enough: `PushedBackup` is a frozen dataclass, and
        # a field with no default is not an attribute of the class — only of an
        # instance, which there is no way to make here without a server.
        available = set(dir(owner))
        if dataclasses.is_dataclass(owner):
            available |= {field.name for field in dataclasses.fields(owner)}

        # Digits belong to the name: `pushed.sha256` truncated to `sha` would
        # be a test asserting against an attribute nobody wrote.
        for attribute in set(re.findall(rf"\b{variable}\.([a-z_0-9]+)", readme)):
            assert attribute in available, (
                f"the README uses {variable}.{attribute}, which {owner.__name__} does not have"
            )
            seen += 1
    assert seen >= 5, "the README stopped showing the library's surface"


# ------------------------------------------------------------------ settings


def test_every_variable_the_readme_names_is_one_the_cli_reads(readme: str, tmp_path, capsys):
    """Each one is removed in turn, and the CLI has to miss it **by name**.

    This is stronger than comparing two lists: it fails both for a variable the
    README invents and for one the CLI stopped reading, and it does it through
    the code path an operator meets — `datavalv push` with the configuration
    incomplete, which exits 3 before a single request is made.

    The message matters as much as the code. A variable this client never reads
    would leave the other three in place, the command would fail three lines
    later for an unrelated reason, and exit 3 all the same.
    """
    everything = set(re.findall(r"\bDATAVALV_[A-Z_]+\b", readme))
    # One variable is optional and so cannot be "missed by name": where the
    # vault-key pins are kept. It is checked against the module that reads it
    # rather than against a failure, and `test_pins.py` proves it is honoured.
    assert everything >= {pins.ENV_VAR}, "the README no longer says where the pins are kept"
    named = sorted(everything - {pins.ENV_VAR})
    assert named, "the README no longer documents any settings"

    key = tmp_path / "datavalv-signing.pem"
    key.write_text("-----BEGIN PRIVATE KEY-----\nnot a real key\n-----END PRIVATE KEY-----\n")
    key.chmod(0o600)

    complete = {
        "DATAVALV_API": "https://api.datavalv.se",
        "DATAVALV_CLIENT_ID": "9fd31abd-e7ac-4d06-97c9-f9125f829bc4",
        "DATAVALV_KEY_ID": "3783178c-9fe3-4a1c-aba5-6a4ee9478a5c",
        "DATAVALV_PRIVATE_KEY": str(key),
    }
    assert named == sorted(complete), f"the README names {named}"

    dump = tmp_path / "dump.sql.gz"
    dump.write_bytes(b"-- a dump\n")

    for missing in named:
        environment = {name: value for name, value in complete.items() if name != missing}
        with pytest.MonkeyPatch.context() as patch:
            for name in complete:
                patch.delenv(name, raising=False)
            for name, value in environment.items():
                patch.setenv(name, value)

            code = cli.main(["push", str(dump), "--external-id", "kund-4711"])

        assert code == cli.EXIT_CONFIG, f"{missing} missing should be a configuration failure"
        assert f"set {missing}" in capsys.readouterr().err, (
            f"the README names {missing}, and leaving it out is not what the CLI complained about"
        )


def test_the_readme_says_the_key_setting_is_a_path_and_why(readme: str):
    """The one settings mistake with a cost.

    `_read_private_key` refuses a PEM in `DATAVALV_PRIVATE_KEY` and refuses to
    echo it back, and from the outside that looks like an unhelpful client
    unless the document that sent the operator there says what it is for. The
    wrapping is normalised away first: this is about what the README says, not
    where its lines happen to break.
    """
    prose = " ".join(readme.split())
    assert "the **path** to the key" in prose
    for reason in ("in `ps`", "shell history", "crash dump"):
        assert reason in prose, f"the README no longer says why: {reason}"


# ---------------------------------------------------------------- exit codes


def _readme_exit_codes(text: str) -> dict[int, str]:
    """The `| 5 | ... |` rows of the exit-code table."""
    return {
        int(code): description.strip()
        for code, description in re.findall(r"^\|\s*(\d)\s*\|\s*(.+?)\s*\|$", text, re.MULTILINE)
    }


def _cli_exit_codes() -> dict[int, str]:
    codes = {}
    for line in cli._EXIT_TABLE.splitlines()[1:]:
        code, description = line.strip().split("  ", 1)
        codes[int(code)] = description.strip()
    return codes


def test_the_exit_code_table_is_the_cli_s_own(readme: str):
    """A schedule branches on these numbers. The README and `--help` disagreeing
    about what 5 means is the defect that gets somebody paged for a vault whose
    owner simply has not signed in yet."""
    assert _readme_exit_codes(readme) == _cli_exit_codes()


def test_the_documented_codes_are_the_constants_the_cli_returns(readme: str):
    """And the table is not just internally consistent prose: these are the
    values `main` actually answers with."""
    documented = _readme_exit_codes(readme)
    assert set(documented) == {
        cli.EXIT_OK,
        cli.EXIT_FAILED,
        cli.EXIT_USAGE,
        cli.EXIT_CONFIG,
        cli.EXIT_AUTH,
        cli.EXIT_RETRY,
        cli.EXIT_REFUSED,
        cli.EXIT_KEY_CHANGED,
    }
    assert "run it again later" in documented[cli.EXIT_RETRY]
