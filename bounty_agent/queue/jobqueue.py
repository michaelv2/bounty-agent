"""Persistent SQLite job queue for the local-LLM lane (SPEC.md §0).

llm-server handles one request at a time, so local work (triage, summaries,
policy parsing) is queued and drained by a worker, overnight or whenever the
server is idle. Jobs survive restarts. A job stuck in 'running' (e.g. the worker
crashed) is put back in the queue by `requeue_stale()`.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

Handler = Callable[[dict[str, Any]], Any]


@dataclass(frozen=True)
class Job:
    id: int
    kind: str
    payload: dict[str, Any]
    attempts: int
    max_attempts: int


class JobQueue:
    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn

    def enqueue(self, kind: str, payload: dict[str, Any], *, priority: int = 0, max_attempts: int = 3) -> int:
        cur = self.conn.execute(
            "INSERT INTO jobs (kind, payload, priority, max_attempts) VALUES (?, ?, ?, ?)",
            (kind, json.dumps(payload), priority, max_attempts),
        )
        return cur.lastrowid

    def claim(self) -> Job | None:
        """Atomically take the highest-priority, oldest queued job."""
        row = self.conn.execute(
            """UPDATE jobs
               SET state = 'running', attempts = attempts + 1, claimed_at = datetime('now')
               WHERE id = (SELECT id FROM jobs WHERE state = 'queued' AND attempts < max_attempts
                           ORDER BY priority DESC, id ASC LIMIT 1)
               RETURNING id, kind, payload, attempts, max_attempts"""
        ).fetchone()
        if row is None:
            return None
        return Job(row["id"], row["kind"], json.loads(row["payload"]), row["attempts"], row["max_attempts"])

    def complete(self, job_id: int, result: Any = None) -> None:
        self.conn.execute(
            "UPDATE jobs SET state = 'done', result = ?, finished_at = datetime('now') WHERE id = ?",
            (json.dumps(result), job_id),
        )

    def fail(self, job_id: int, error: str) -> None:
        """Record a failure. The job is retried until it runs out of attempts."""
        self.conn.execute(
            """UPDATE jobs
               SET error = ?,
                   state = CASE WHEN attempts >= max_attempts THEN 'failed' ELSE 'queued' END,
                   finished_at = CASE WHEN attempts >= max_attempts THEN datetime('now') END
               WHERE id = ?""",
            (error, job_id),
        )

    def requeue_stale(self, older_than_minutes: int = 60) -> int:
        cur = self.conn.execute(
            """UPDATE jobs
               SET state = CASE WHEN attempts >= max_attempts THEN 'failed' ELSE 'queued' END,
                   error = CASE WHEN attempts >= max_attempts
                                THEN 'worker died or hung on every attempt' ELSE error END,
                   finished_at = CASE WHEN attempts >= max_attempts THEN datetime('now') END
               WHERE state = 'running' AND claimed_at < datetime('now', ?)""",
            (f"-{older_than_minutes} minutes",),
        )
        return cur.rowcount

    def counts(self) -> dict[str, int]:
        rows = self.conn.execute("SELECT state, COUNT(*) AS n FROM jobs GROUP BY state").fetchall()
        return {r["state"]: r["n"] for r in rows}


def run_once(queue: JobQueue, handlers: dict[str, Handler]) -> bool:
    """Claim and run one job. Returns False when the queue is empty.

    A job whose kind has no handler fails at once (no retries). That is a
    programming error, and retrying won't fix it.
    """
    job = queue.claim()
    if job is None:
        return False
    handler = handlers.get(job.kind)
    if handler is None:
        queue.conn.execute("UPDATE jobs SET max_attempts = attempts WHERE id = ?", (job.id,))
        queue.fail(job.id, f"no handler registered for job kind {job.kind!r}")
        return True
    try:
        queue.complete(job.id, handler(job.payload))
    except Exception as exc:  # noqa: BLE001  - record any handler failure, keep the worker alive
        queue.fail(job.id, f"{type(exc).__name__}: {exc}")
    return True


def drain(queue: JobQueue, handlers: dict[str, Handler], *, max_jobs: int | None = None) -> int:
    """Run jobs serially until the queue is empty (or `max_jobs` have run)."""
    n = 0
    while (max_jobs is None or n < max_jobs) and run_once(queue, handlers):
        n += 1
    return n
