"""`CHANGELOG.md`: what changed in each release, newest first.

The one document a reader opens to answer "what is different since the
version I have", and so the one that is wrong in the most expensive way when
it lags: a release whose entry was never written reads as a release in which
nothing changed. So the top entry has to be the version this package says it
is, and a bump without an entry fails here rather than ships.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

import datavalv_client

CLIENT = Path(__file__).resolve().parents[1]
CHANGELOG = CLIENT / "CHANGELOG.md"

#: `## 0.7.0 — 2026-10-13`: the version, and the day it was prepared.
ENTRY = re.compile(r"^## (\d+\.\d+\.\d+) — (\d{4}-\d{2}-\d{2})$", re.MULTILINE)


def _entries() -> list[tuple[str, str]]:
    return ENTRY.findall(CHANGELOG.read_text())


def _as_tuple(version: str) -> tuple[int, ...]:
    return tuple(int(part) for part in version.split("."))


def test_the_newest_entry_is_the_version_this_package_says_it_is():
    entries = _entries()
    assert entries, "no `## X.Y.Z — YYYY-MM-DD` entry at all"
    assert entries[0][0] == datavalv_client.__version__


def test_every_release_is_there_once_and_newest_first():
    versions = [version for version, _ in _entries()]
    assert len(versions) == len(set(versions)), versions
    assert versions == sorted(versions, key=_as_tuple, reverse=True), versions
    # Every version ever published to PyPI. A changelog that starts at the
    # release it was written for says nothing about the ones before it.
    for published in ("0.5.0", "0.5.1", "0.6.0"):
        assert published in versions, published


def test_the_dates_never_go_forward_as_the_versions_go_back():
    dates = [date for _, date in _entries()]
    assert dates == sorted(dates, reverse=True), dates


def test_the_index_page_links_to_it():
    """PyPI shows `project.urls` in its sidebar, and the mirror is where the
    file can be read: the wheel carries the README, not this."""
    urls = tomllib.loads((CLIENT / "pyproject.toml").read_text())["project"]["urls"]
    assert urls.get("Changelog", "").endswith("/client/CHANGELOG.md"), urls
