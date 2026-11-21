"""SQLite storage. One file, one schema. See SPEC.md §6."""

from __future__ import annotations

import sqlite3
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS programs (
    id          INTEGER PRIMARY KEY,
    platform    TEXT NOT NULL,             -- code4rena, sherlock, immunefi, ...
    slug        TEXT NOT NULL,
    name        TEXT,
    url         TEXT,
    max_payout_usd REAL,
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE (platform, slug)
);

CREATE TABLE IF NOT EXISTS policies (
    id              INTEGER PRIMARY KEY,
    program_id      INTEGER NOT NULL REFERENCES programs(id),
    policy_json     TEXT NOT NULL,         -- serialized scope.Policy
    source_hash     TEXT,                  -- hash of the raw policy text it was parsed from
    human_confirmed INTEGER NOT NULL DEFAULT 0,
    confirmed_at    TEXT,
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS targets (
    id          INTEGER PRIMARY KEY,
    program_id  INTEGER REFERENCES programs(id),
    kind        TEXT NOT NULL,             -- repo | contract | contest-archive
    locator     TEXT NOT NULL,             -- repo URL, chain:address, ...
    pinned_ref  TEXT NOT NULL,             -- commit SHA or block number
    snapshot_hash TEXT,
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS hotspots (
    id          INTEGER PRIMARY KEY,
    target_id   INTEGER NOT NULL REFERENCES targets(id),
    path        TEXT NOT NULL,
    rank        INTEGER,
    rationale   TEXT
);

CREATE TABLE IF NOT EXISTS hypotheses (
    id          INTEGER PRIMARY KEY,
    hotspot_id  INTEGER NOT NULL REFERENCES hotspots(id),
    summary     TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'open'   -- open | poc_written | dropped
);

CREATE TABLE IF NOT EXISTS pocs (
    id            INTEGER PRIMARY KEY,
    hypothesis_id INTEGER NOT NULL REFERENCES hypotheses(id),
    path          TEXT NOT NULL,
    status        TEXT NOT NULL DEFAULT 'pending',  -- pending | passed | failed
    cheat_flags   TEXT,                             -- JSON list from validate.cheatlint
    log           TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    id          INTEGER PRIMARY KEY,
    poc_id      INTEGER NOT NULL REFERENCES pocs(id),
    title       TEXT NOT NULL,
    severity    TEXT,
    novelty     REAL,
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS reviews (
    id          INTEGER PRIMARY KEY,
    finding_id  INTEGER NOT NULL REFERENCES findings(id),
    reviewer    TEXT NOT NULL,             -- skeptic model ID, or 'human'
    verdict     TEXT NOT NULL,             -- submit | reject | flag-for-human
    confidence  REAL,
    concerns    TEXT,
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS submissions (
    id          INTEGER PRIMARY KEY,
    finding_id  INTEGER NOT NULL REFERENCES findings(id),
    platform    TEXT NOT NULL,
    status      TEXT NOT NULL,             -- submitted | accepted | duplicate | informative | invalid
    payout_usd  REAL,
    submitted_at TEXT                      -- set by the human who submitted it manually
);

CREATE TABLE IF NOT EXISTS costs (
    id            INTEGER PRIMARY KEY,
    ts            TEXT NOT NULL DEFAULT (datetime('now')),
    stage         TEXT NOT NULL,
    model         TEXT NOT NULL,
    target_id     INTEGER,
    input_tokens  INTEGER NOT NULL DEFAULT 0,
    output_tokens INTEGER NOT NULL DEFAULT 0,
    cache_read_tokens  INTEGER NOT NULL DEFAULT 0,
    cache_write_tokens INTEGER NOT NULL DEFAULT 0,
    batch         INTEGER NOT NULL DEFAULT 0,
    usd           REAL NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_costs_ts ON costs(ts);
CREATE INDEX IF NOT EXISTS idx_costs_target ON costs(target_id);

-- Message Batches API (50% off, results within 24h). Pending items reserve their
-- worst-case cost against the budget caps until their results are collected.
CREATE TABLE IF NOT EXISTS batches (
    id          TEXT PRIMARY KEY,          -- local id, created before the API call
    api_id      TEXT,                      -- Anthropic batch id, set once the batch is created
    stage       TEXT NOT NULL,
    model       TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'reserving',  -- reserving | in_progress | ended
    created_ts  TEXT NOT NULL,
    ended_ts    TEXT
);

CREATE TABLE IF NOT EXISTS batch_items (
    batch_id     TEXT NOT NULL REFERENCES batches(id),
    custom_id    TEXT NOT NULL,
    target_id    INTEGER,
    estimate_usd REAL NOT NULL,
    state        TEXT NOT NULL DEFAULT 'pending',  -- pending | succeeded | errored | canceled | expired
    result_text  TEXT,
    error        TEXT,
    PRIMARY KEY (batch_id, custom_id)
);

CREATE TABLE IF NOT EXISTS jobs (
    id          INTEGER PRIMARY KEY,
    kind        TEXT NOT NULL,
    payload     TEXT NOT NULL,             -- JSON
    priority    INTEGER NOT NULL DEFAULT 0,  -- higher runs first
    state       TEXT NOT NULL DEFAULT 'queued',  -- queued | running | done | failed
    attempts    INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL DEFAULT 3,
    result      TEXT,
    error       TEXT,
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    claimed_at  TEXT,
    finished_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_jobs_state ON jobs(state, priority);
"""


def connect(path: Path | str) -> sqlite3.Connection:
    """Open the database, creating the file and schema if needed."""
    if str(path) != ":memory:":
        Path(path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, isolation_level=None)  # autocommit; use explicit BEGIN where needed
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.executescript(SCHEMA)
    _migrate(conn)
    return conn


def _migrate(conn: sqlite3.Connection) -> None:
    """Small in-place upgrades for databases created by older versions."""
    cols = {r["name"] for r in conn.execute("PRAGMA table_info(batches)")}
    if "api_id" not in cols:
        conn.execute("ALTER TABLE batches ADD COLUMN api_id TEXT")
        conn.execute("UPDATE batches SET api_id = id WHERE api_id IS NULL")  # old rows used the API id as id
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_batches_api ON batches(api_id)")
