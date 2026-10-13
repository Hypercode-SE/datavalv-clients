"""The Python sample on datavalv.se/developers, run rather than read.

The page is a promise somebody will act on at a terminal, and this project has
already shipped two samples that named things nobody could get. The defence
that worked for `README.md` is `test_readme.py`: the document is the source and
the test is the only copy. This file does the same for the web page — with the
one upgrade the page's sample makes possible, now that it is library code
instead of raw HTTP.

**It is executed.** The block is lifted out of
`web/src/app/pages/developers/developers.ts`, stripped of its syntax
highlighting, and run against the installed client and the `FakeDatavalv` in
`conftest.py` — which verifies every token, refuses a replayed `jti`, and
refuses an upload whose checksum header disagrees with its body. So a renamed
keyword argument, a renamed method, a renamed attribute on the result, or a
sample that quietly stopped encrypting anything fails here, in the words of a
Python traceback, rather than in a customer's terminal.

Three things are supplied that the page cannot show and a reader has to bring:
`CLIENT_ID` and `KEY_ID`, which `/connect-system` step 04 hands back, and the
two files the sample opens. Everything else is the page's own text, executed as
written.

What this does NOT check is whether the prose around the sample is true.
Nothing can. It checks the part that rots silently, which is the part a reader
copies.
"""

from __future__ import annotations

import base64
import hashlib
import html
import io
import re
import tomllib
from pathlib import Path

import httpx
import pytest
from conftest import BACKUP_ID, CLIENT_ID, EXTERNAL_ID, KEY_ID, FakeDatavalv

from datavalv_client import crypto

#: The page, in the Angular application. Read as text: nothing here renders a
#: template, and the sample is a literal in the component's source.
PAGE = (
    Path(__file__).resolve().parents[2]
    / "web"
    / "src"
    / "app"
    / "pages"
    / "developers"
    / "developers.ts"
)

#: The signing key's path in the sample, and the dump's. Both are opened by the
#: code under test, and neither exists on the machine running this.
KEY_PATH = "/etc/datavalv/datavalv-signing.pem"
DUMP_PATH = "/var/backups/kund-4711.sql.gz"

#: What the sample says it is pushing. The bytes are this test's; the filename
#: and the label are the page's.
DUMP = b"-- a database dump, or near enough\n" * 64
NAME = "kund-4711.sql.gz"
LABEL = "nightly"

#: The five calls this sample makes: one vault, then the four a backup costs.
#: `Call.step` spells them, and the order is the only one in which a backup
#: exists at the end.
EXPECTED_CALLS = [
    "POST /v1/tenants",
    f"GET /v1/tenants/{EXTERNAL_ID}/public-key",
    f"POST /v1/tenants/{EXTERNAL_ID}/backups",
    "PUT upload",
    f"POST /v1/backups/{BACKUP_ID}/complete",
]


def _code_blocks(page: str) -> list[str]:
    """Every `<pre class="pub-code …">` block, as a reader sees it.

    The blocks are syntax-highlighted with `<span>`s and carry HTML entities —
    braces would open an ICU expansion in an Angular template and a bare `@`
    would open a control-flow block — so the markup is removed and the entities
    are decoded. What comes back is the text on screen, which is the text
    somebody copies.
    """
    blocks = re.findall(r'<pre\b[^>]*class="pub-code[^"]*"[^>]*>(.*?)</pre>', page, re.DOTALL)
    return [html.unescape(re.sub(r"<[^>]+>", "", block)) for block in blocks]


@pytest.fixture(scope="module")
def sample() -> str:
    """The one block on the page that imports this package."""
    blocks = [block for block in _code_blocks(PAGE.read_text()) if "datavalv_client" in block]
    assert len(blocks) == 1, (
        f"{PAGE.name} shows {len(blocks)} Python samples importing datavalv_client; "
        "this test runs exactly one"
    )
    return blocks[0]


def test_the_page_still_shows_a_python_sample(sample: str):
    """The guard under the guard.

    Every assertion below is about a block of code. A page that had lost it —
    or that had gone back to raw HTTP, which imports nothing — would make them
    all pass by having nothing to run.
    """
    assert "from datavalv_client import DatavalvClient" in sample
    assert "push_backup" in sample


def test_the_sample_is_python(sample: str):
    compile(sample, str(PAGE), "exec")


def _execute(
    sample: str,
    *,
    service: FakeDatavalv,
    signing_key_pem: str,
    monkeypatch: pytest.MonkeyPatch,
) -> list[tuple]:
    """Run the sample, and return whatever it printed.

    The three seams are the three things the page cannot show a reader: the two
    identifiers `/connect-system` step 04 issues, the files the sample opens,
    and the socket. Nothing else is stubbed — the client builds and signs real
    requests, and `FakeDatavalv` verifies them.
    """
    real_client = httpx.Client
    transport = httpx.MockTransport(service)

    def client_on_the_fake(**kwargs) -> httpx.Client:
        return real_client(**{**kwargs, "transport": transport})

    monkeypatch.setattr(httpx, "Client", client_on_the_fake)

    read_text = Path.read_text

    def signing_key_file(self: Path, *args, **kwargs) -> str:
        if str(self) == KEY_PATH:
            return signing_key_pem
        return read_text(self, *args, **kwargs)  # pragma: no cover - not reached

    monkeypatch.setattr(Path, "read_text", signing_key_file)

    def dump_file(path, mode="r", *args, **kwargs):
        assert (str(path), mode) == (DUMP_PATH, "rb"), (
            f"the sample opens {path!r} in mode {mode!r}, which this test does not fake"
        )
        return io.BytesIO(DUMP)

    printed: list[tuple] = []
    namespace = {
        "CLIENT_ID": CLIENT_ID,
        "KEY_ID": KEY_ID,
        # Shadowing the builtins rather than patching them: a name in the
        # globals a module is executed in is found before the builtin of the
        # same name, and the sample is executed as a module.
        "open": dump_file,
        "print": lambda *values: printed.append(values),
    }
    exec(compile(sample, str(PAGE), "exec"), namespace)  # noqa: S102
    return printed


def test_the_sample_makes_the_calls_it_says_it_makes(
    sample: str, service, signing_key_pem, monkeypatch
):
    """The page's own claim, checked against the wire it produces.

    `FakeDatavalv` is not a lenient double: every Datavalv call has to carry a
    token it can verify, a `jti` is accepted once, and the presigned PUT is
    refused unless `x-amz-checksum-sha256` matches the body. A sample that
    hoisted a header, skipped the confirmation, or uploaded something other
    than what it registered does not get this far.
    """
    _execute(sample, service=service, signing_key_pem=signing_key_pem, monkeypatch=monkeypatch)

    assert [call.step for call in service.calls] == EXPECTED_CALLS


def test_what_the_sample_uploads_is_the_file_it_was_given(
    sample: str, service, signing_key_pem, tenant_key, monkeypatch
):
    """Encrypted on the way out, and openable only with the vault's key.

    This is the page's headline — "kopian är krypterad innan den lämnar
    servern" — as an assertion. The uploaded bytes are not the dump, the
    wrapped key unwraps with the tenant's private key, and what comes out is
    the dump exactly.
    """
    _execute(sample, service=service, signing_key_pem=signing_key_pem, monkeypatch=monkeypatch)

    registered = next(
        call for call in service.calls if call.step.endswith(f"/tenants/{EXTERNAL_ID}/backups")
    ).json()
    assert service.uploaded is not None
    assert DUMP not in service.uploaded
    assert registered["size"] == len(service.uploaded)
    assert registered["sha256"] == hashlib.sha256(service.uploaded).hexdigest()

    dek = crypto.unwrap_dek(base64.b64decode(registered["wrappedDekB64"]), tenant_key)
    assert crypto.decrypt(service.uploaded, dek) == DUMP


def test_the_sample_sends_the_filename_encrypted_and_the_label_in_the_clear(
    sample: str, service, signing_key_pem, tenant_key, monkeypatch
):
    """The one difference the page states in a comment, on the wire.

    `/security` lists the label among the things an operator can read and the
    filename among the things nobody can, and `/developers` says so beside this
    sample. Both pages are describing these two fields: `label` arrives as
    typed, `nameCipherB64` arrives as a v1 blob that needs the vault's key.
    """
    _execute(sample, service=service, signing_key_pem=signing_key_pem, monkeypatch=monkeypatch)

    registered = next(
        call for call in service.calls if call.step.endswith(f"/tenants/{EXTERNAL_ID}/backups")
    ).json()

    assert registered["label"] == LABEL
    assert NAME not in str(registered), "the filename reached the service in the clear"

    dek = crypto.unwrap_dek(base64.b64decode(registered["wrappedDekB64"]), tenant_key)
    name_blob = base64.b64decode(registered["nameCipherB64"])
    assert crypto.decrypt(name_blob, dek).decode() == NAME


def test_the_sample_prints_fields_the_result_really_has(
    sample: str, service, signing_key_pem, monkeypatch
):
    """`pushed.backup_id`, `pushed.size`, `pushed.sha256` — the three names the
    page tells a reader to read off the result.

    A renamed field raises `AttributeError` inside `_execute` rather than
    reaching this assertion, which is the point; what is asserted here is that
    the values are the ones the service actually issued, so a sample printing
    three constants would fail too.
    """
    printed = _execute(
        sample, service=service, signing_key_pem=signing_key_pem, monkeypatch=monkeypatch
    )

    assert service.uploaded is not None
    assert printed == [
        (BACKUP_ID, len(service.uploaded), hashlib.sha256(service.uploaded).hexdigest())
    ]


def test_the_page_installs_the_package_this_directory_publishes():
    """`/developers` and `/connect-system` print `pip install datavalv-client`,
    and `public-pages.spec.ts` holds the web side to that exact line -- but
    the web build cannot read `pyproject.toml`, so the name there is written
    down. This is the other half: the name on both pages is the one PyPI
    knows this package by.

    Read as text, like the sample: the line is a literal in each component.
    """
    pyproject = Path(__file__).resolve().parents[1] / "pyproject.toml"
    name = tomllib.loads(pyproject.read_text())["project"]["name"]
    # The line ends where the name does: inside a code block it is followed by
    # a newline, and in a span by the closing tag. Neither may be a longer
    # package name that merely starts with this one.
    line = re.compile(rf"pip install {re.escape(name)}(?![\w.-])")
    for page in (PAGE, PAGE.parents[1] / "connect-system" / "connect-system.ts"):
        assert line.search(page.read_text()), page.name
