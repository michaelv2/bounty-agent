"""Target manifest (config/targets.toml) -> targets table.

Each entry:

    [[target]]
    name = "dvd-unstoppable"                      # unique, [a-z0-9-]
    source = "practice"                           # practice | backtest | program
    url = "https://github.com/theredguild/damn-vulnerable-defi"
    ref = "64fddf9f96de2782f8868898d68673acb295119c"   # tag, branch or SHA (pinned at fetch)
    include = ["src/unstoppable/*.sol"]           # files to triage (default: src/**/*.sol)

`practice` and `backtest` targets have no bounty program: they are CTFs and past
contests, analyzed offline. `program` targets are real bounty programs and are only
processed once a human-confirmed policy allows each action (scope.check). Until the
intel stage exists, there is no way to confirm one, so they are refused. Deny by default.
"""

from __future__ import annotations

import json
import re
import sqlite3
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from bounty_agent.fetch import validate_url

SOURCES = ("practice", "backtest", "program")
DEFAULT_INCLUDE = ["src/**/*.sol"]
_NAME = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
_GLOB = re.compile(r"^[A-Za-z0-9_*./-]+$")


class ManifestError(ValueError):
    pass


@dataclass(frozen=True)
class TargetSpec:
    name: str
    source: str
    url: str
    ref: str
    include: list[str] = field(default_factory=lambda: list(DEFAULT_INCLUDE))


def load_manifest(path: Path) -> list[TargetSpec]:
    if not path.exists():
        return []
    try:
        raw = tomllib.loads(path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as exc:
        raise ManifestError(f"{path}: {exc}") from None
    specs, names = [], set()
    for i, t in enumerate(raw.get("target", [])):
        where = f"{path}: target #{i + 1}"
        name = t.get("name", "")
        if not _NAME.match(name):
            raise ManifestError(f"{where}: name must match {_NAME.pattern}")
        if name in names:
            raise ManifestError(f"{where}: duplicate name {name!r}")
        source = t.get("source")
        if source not in SOURCES:
            raise ManifestError(f"{where}: source must be one of {SOURCES}")
        include = t.get("include", list(DEFAULT_INCLUDE))
        if not include or not all(isinstance(g, str) and _GLOB.match(g) and ".." not in g
                                  and not g.startswith("/") for g in include):
            raise ManifestError(f"{where}: include must be relative globs without '..'")
        try:
            url = validate_url(t.get("url", ""))
        except Exception as exc:
            raise ManifestError(f"{where}: {exc}") from None
        ref = t.get("ref", "")
        if not isinstance(ref, str) or not ref:
            raise ManifestError(f"{where}: ref is required")
        names.add(name)
        specs.append(TargetSpec(name, source, url, ref, include))
    return specs


def sync_targets(conn: sqlite3.Connection, specs: list[TargetSpec]) -> list[int]:
    """Insert new targets; leave existing ones (and their progress) alone unless url/ref changed."""
    ids = []
    for s in specs:
        row = conn.execute("SELECT id, locator, pinned_ref, stage FROM targets WHERE name = ?", (s.name,)).fetchone()
        if row is None:
            cur = conn.execute(
                """INSERT INTO targets (name, source, kind, locator, pinned_ref, include_json, stage, updated_at)
                   VALUES (?, ?, 'repo', ?, ?, ?, 'new', datetime('now'))""",
                (s.name, s.source, s.url, s.ref, json.dumps(s.include)),
            )
            ids.append(cur.lastrowid)
            continue
        ids.append(row["id"])
        changed_source = row["locator"] != s.url or (row["stage"] == "new" and row["pinned_ref"] != s.ref)
        conn.execute("UPDATE targets SET source = ?, include_json = ? WHERE id = ?",
                     (s.source, json.dumps(s.include), row["id"]))
        if changed_source:
            # A different repo means a different target: start over.
            conn.execute(
                """UPDATE targets SET locator = ?, pinned_ref = ?, stage = 'new', stage_error = NULL,
                   failures = 0, snapshot_path = NULL, snapshot_hash = NULL, updated_at = datetime('now')
                   WHERE id = ?""",
                (s.url, s.ref, row["id"]),
            )
    return ids
