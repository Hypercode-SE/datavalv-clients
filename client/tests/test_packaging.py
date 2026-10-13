"""The package as somebody else receives it: built, installed, and run from the
install rather than from this checkout.

Everything else in this suite imports `datavalv_client` from `src/`, where every
file is present because git says so. A wheel is a different question — it
contains what the build backend decided to put in it — and the two ways that
goes wrong are both silent:

* **`_format_constants.py` is generated** (`scripts/gen_constants.py`) rather
  than written, and a generated file is the natural thing to add to
  `.gitignore`. Hatchling's default selection is "everything the VCS does not
  ignore", so that one line would produce a wheel that installs cleanly, passes
  `pip check`, and raises `ImportError` on `import datavalv_client`.
* **A package that builds is not a package that installs.** A console script
  that names a module that is not in the wheel, a dependency left out of
  `dependencies`, metadata the index rejects: none of it is visible from a
  source tree where the imports resolve anyway.

So this builds the real wheel with the real command and installs it into a
throwaway virtualenv that has nothing else in it. `datavalv --help` run from
there is the whole claim the release makes.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
import tomllib
import zipfile
from collections.abc import Iterator
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
CLIENT = ROOT / "client"
PACKAGE = "datavalv_client"


def _run(command: list[str], **kwargs) -> subprocess.CompletedProcess[str]:
    """Run, and on failure report what it said rather than a bare exit code."""
    done = subprocess.run(command, capture_output=True, text=True, check=False, **kwargs)
    if done.returncode != 0:
        pytest.fail(
            f"{' '.join(command)} exited {done.returncode}\n"
            f"--- stdout ---\n{done.stdout}\n--- stderr ---\n{done.stderr}"
        )
    return done


@pytest.fixture(scope="session")
def uv() -> str:
    found = shutil.which("uv")
    if found is None:  # pragma: no cover - uv is how this suite is run at all
        pytest.fail("uv is not on PATH, and all Python work in this project runs through it")
    return found


@pytest.fixture(scope="session")
def wheel(uv: str, tmp_path_factory: pytest.TempPathFactory) -> Path:
    """The wheel `RELEASING.md` uploads, built by the command it names."""
    out = tmp_path_factory.mktemp("dist")
    _run([uv, "build", "--wheel", "--out-dir", str(out), str(CLIENT)], cwd=ROOT)
    built = sorted(out.glob("*.whl"))
    assert len(built) == 1, f"expected one wheel, got {[p.name for p in built]}"
    return built[0]


@pytest.fixture(scope="session")
def installed(uv: str, wheel: Path, tmp_path_factory: pytest.TempPathFactory) -> Iterator[Path]:
    """A virtualenv with the wheel in it and nothing of this checkout.

    Built against the interpreter running the tests, so the environment agrees
    with `requires-python` the same way a user's would. Removed afterwards: it
    is a few tens of megabytes of throwaway.
    """
    venv = tmp_path_factory.mktemp("install") / "venv"
    _run([uv, "venv", "--python", sys.executable, str(venv)])
    python = venv / "bin" / "python"
    _run([uv, "pip", "install", "--python", str(python), str(wheel)])
    yield venv
    shutil.rmtree(venv, ignore_errors=True)


def _names(wheel: Path) -> list[str]:
    with zipfile.ZipFile(wheel) as archive:
        return archive.namelist()


def _dist_info(wheel: Path, filename: str) -> str:
    with zipfile.ZipFile(wheel) as archive:
        name = next(n for n in archive.namelist() if n.endswith(f".dist-info/{filename}"))
        return archive.read(name).decode()


# ------------------------------------------------------------------ contents


def test_the_wheel_carries_the_generated_constants(wheel: Path):
    """Without this file the package imports nothing at all.

    `crypto` and `format` both import from it at module scope, and `__init__`
    imports both, so a wheel missing it fails on the first line of the first
    import — after a completely successful installation.
    """
    assert f"{PACKAGE}/_format_constants.py" in _names(wheel)

    with zipfile.ZipFile(wheel) as archive:
        shipped = archive.read(f"{PACKAGE}/_format_constants.py")
    committed = (CLIENT / "src" / PACKAGE / "_format_constants.py").read_bytes()
    assert shipped == committed, "the wheel's constants are not the committed ones"


def test_the_wheel_carries_every_module_of_the_package(wheel: Path):
    """Named one by one rather than counted, so a module that stops being
    shipped is reported by name."""
    source = CLIENT / "src" / PACKAGE
    expected = {f"{PACKAGE}/{path.name}" for path in source.glob("*.py")}
    assert expected <= set(_names(wheel))


def test_the_wheel_declares_the_datavalv_command(wheel: Path):
    entry_points = _dist_info(wheel, "entry_points.txt")
    assert "datavalv = datavalv_client.cli:main" in entry_points


def test_the_wheel_carries_the_licence(wheel: Path):
    assert any(name.endswith("licenses/LICENSE") for name in _names(wheel))


# ------------------------------------------------------------------ metadata


def test_the_metadata_says_what_an_index_and_a_reader_need(wheel: Path):
    metadata = _dist_info(wheel, "METADATA")

    assert "License-Expression: MIT" in metadata
    assert "Requires-Python: >=3.13" in metadata
    # The README is the long description. Without the content type an index
    # renders the markdown as plain text.
    assert "Description-Content-Type: text/markdown" in metadata
    assert "# datavalv-client" in metadata

    for url in (
        "Project-URL: Homepage, https://datavalv.se",
        "Project-URL: Documentation, https://datavalv.se/connect-system",
        "Project-URL: Source, https://github.com/Hypercode-SE/datavalv",
    ):
        assert url in metadata

    assert "Classifier: Programming Language :: Python :: 3.13" in metadata
    # PEP 639: the SPDX expression above replaces these, and an upload carrying
    # both is refused.
    assert "Classifier: License ::" not in metadata

    for dependency in ("cryptography>=44", "httpx>=0.28", "pyjwt[crypto]>=2.10"):
        assert f"Requires-Dist: {dependency}" in metadata


def test_one_version_in_three_places(wheel: Path):
    """`pyproject.toml`, `__version__` and the built filename.

    Two of them are hand-maintained and drift apart quietly; the third is what a
    user ends up with. `RELEASING.md` says to bump both by hand, which is
    exactly the kind of instruction this test exists to enforce.
    """
    declared = tomllib.loads((CLIENT / "pyproject.toml").read_text())["project"]["version"]

    source = (CLIENT / "src" / PACKAGE / "__init__.py").read_text()
    in_code = re.search(r'__version__ = "([^"]+)"', source)
    assert in_code is not None, "__init__.py no longer declares __version__"

    assert in_code.group(1) == declared
    assert wheel.name == f"{PACKAGE}-{declared}-py3-none-any.whl"


# ------------------------------------------------------------------ installed


def test_the_command_runs_from_an_installed_wheel(installed: Path):
    """`datavalv --help`, from the install, with this source tree nowhere near it."""
    datavalv = installed / "bin" / "datavalv"
    assert datavalv.exists(), "the wheel installed no `datavalv` command"

    # `cwd` is the venv rather than the repository: run from `client/`, `src/`
    # would not be on `sys.path` either, but the next person to add a
    # `conftest.py` or a `datavalv_client/` directory beside it would not know
    # that this test had quietly started proving something else.
    done = _run([str(datavalv), "--help"], cwd=installed)

    assert "usage: datavalv" in done.stdout
    for command in ("keygen", "vault", "push"):
        assert command in done.stdout
    # The exit-code table is part of `--help` on purpose: an operator reading a
    # failure at 3am should not have to find the README.
    assert "5  nothing is wrong; run it again later" in done.stdout


def test_the_package_imports_from_the_install_and_not_from_this_tree(installed: Path):
    """The import that a missing `_format_constants.py` breaks, run where the
    source tree cannot answer for it."""
    python = installed / "bin" / "python"
    program = (
        "import datavalv_client as m;"
        "from datavalv_client import DatavalvClient, __version__;"
        "from datavalv_client._format_constants import MAGIC;"
        "print(m.__file__); print(__version__); print(MAGIC.decode())"
    )
    done = _run([str(python), "-c", program], cwd=installed)
    imported_from, version, magic = done.stdout.split()

    assert Path(imported_from).is_relative_to(installed), (
        f"the import resolved to {imported_from}, which is not the installed wheel"
    )
    assert not Path(imported_from).is_relative_to(ROOT)
    assert magic == "DVLV"
    assert version == tomllib.loads((CLIENT / "pyproject.toml").read_text())["project"]["version"]


def test_the_install_pulled_in_what_the_client_needs_to_run(installed: Path):
    """A dependency missing from `dependencies` is invisible in a checkout that
    has it anyway. Importing the HTTP and JWT layers from the fresh environment
    is what would notice."""
    python = installed / "bin" / "python"
    _run([str(python), "-c", "import httpx, jwt, cryptography"], cwd=installed)
