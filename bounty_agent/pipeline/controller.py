"""`bounty run`: the deterministic daily controller (SPEC.md §4.2).

Not an LLM. A resumable state machine over the SQLite tables. Each run:
  1. takes a lock (two runs never overlap), records itself in `runs`
  2. requeues jobs left 'running' by a crashed worker; collects finished batches
  3. syncs config/targets.toml into `targets`
  4. advances every target as far as it can go without waiting:
        new -> fetched -> compiler_ready -> triage_queued
  5. drains the local job queue (serially, llm-server serves one request at a time)
     until the queue is empty or the time budget runs out
  6. finishes targets whose triage is done:
        triage_queued -> triaged -> ranked -> awaiting_analysis
  7. stage D (if [analysis] enabled): awaiting_analysis -> analyzed, writing findings
  8. stage F2 (if [review] enabled): unreviewed findings go to the skeptic

Every step is idempotent. A failing step records the error and leaves the target where
it was; after MAX_FAILURES failures the target is 'blocked' until a human resets it.
"""

from __future__ import annotations

import fcntl
import json
import os
import sqlite3
import time
from collections.abc import Callable
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path

from bounty_agent.config import Config
from bounty_agent.fetch import Snapshot, fetch_or_reuse
from bounty_agent.pipeline.targets import load_manifest, sync_targets
from bounty_agent.pipeline.triage import make_triage_handler, rank_hotspots, select_files
from bounty_agent.queue import JobQueue, run_once
from bounty_agent.router import Router
from bounty_agent.sandbox import SolcCache, install_solc, required_solc_versions

MAX_FAILURES = 3
STALE_JOB_MINUTES = 60
TERMINAL = ("awaiting_analysis", "analyzed", "blocked")  # stages advance_all won't touch

Fetcher = Callable[[str, str, Path], Snapshot]
Compiler = Callable[[Path, SolcCache], set[str]]


class AlreadyRunning(RuntimeError):
    pass


@dataclass
class RunSummary:
    run_id: int
    advanced: list[str] = field(default_factory=list)   # "name: from -> to"
    errors: list[str] = field(default_factory=list)
    jobs_run: int = 0
    batches_collected: int = 0
    out_of_time: bool = False
    hotspots_analyzed: int = 0
    findings: int = 0
    reviews: int = 0
    failed_ids: set[int] = field(default_factory=set)   # a target fails at most once per run

    def as_dict(self) -> dict:
        return {"advanced": self.advanced, "errors": self.errors, "jobs_run": self.jobs_run,
                "batches_collected": self.batches_collected, "out_of_time": self.out_of_time,
                "hotspots_analyzed": self.hotspots_analyzed, "findings": self.findings}


@contextmanager
def run_lock(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o644)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise AlreadyRunning(f"another `bounty run` holds {path}") from None
        yield
    finally:
        os.close(fd)  # closing releases the lock


def default_fetcher(url: str, ref: str, snapshots_dir: Path) -> Snapshot:
    return fetch_or_reuse(url, ref, snapshots_dir)


def make_default_compiler(cfg: Config) -> Compiler:
    def compile_ready(snapshot: Path, cache: SolcCache) -> set[str]:
        versions = required_solc_versions(snapshot)
        install_solc(cfg.sandbox, cache, versions)
        cache.verify(versions)
        return versions
    return compile_ready


class Pipeline:
    def __init__(self, cfg: Config, conn: sqlite3.Connection, router: Router, *,
                 manifest: Path, fetcher: Fetcher | None = None, compiler: Compiler | None = None,
                 batch_runner=None, clock: Callable[[], float] = time.monotonic):
        self.cfg = cfg
        self.conn = conn
        self.router = router
        self.manifest = manifest
        self.fetcher = fetcher or default_fetcher
        self.compiler = compiler or make_default_compiler(cfg)
        self.batch_runner = batch_runner
        self.clock = clock
        self.queue = JobQueue(conn)
        self.solc = SolcCache(cfg.data_dir / "solc")
        self.handlers = {"triage_file": make_triage_handler(conn, router)}

    # ------------------------------------------------------------------ helpers
    def _set_stage(self, t: sqlite3.Row, stage: str, summary: RunSummary, **cols) -> None:
        sets = ", ".join(f"{k} = ?" for k in cols)
        self.conn.execute(
            f"UPDATE targets SET stage = ?, stage_error = NULL, updated_at = datetime('now')"
            f"{', ' + sets if sets else ''} WHERE id = ?",
            (stage, *cols.values(), t["id"]),
        )
        summary.advanced.append(f"{t['name']}: {t['stage']} -> {stage}")

    def _fail(self, t: sqlite3.Row, exc: Exception, summary: RunSummary) -> None:
        failures = t["failures"] + 1
        msg = f"{type(exc).__name__}: {exc}"[:500]
        stage_sql = ", stage = 'blocked'" if failures >= MAX_FAILURES else ""
        self.conn.execute(
            f"UPDATE targets SET stage_error = ?, failures = ?, updated_at = datetime('now'){stage_sql} WHERE id = ?",
            (msg, failures, t["id"]),
        )
        summary.errors.append(f"{t['name']} [{t['stage']}]: {msg}")
        summary.failed_ids.add(t["id"])

    def _target(self, target_id: int) -> sqlite3.Row:
        return self.conn.execute("SELECT * FROM targets WHERE id = ?", (target_id,)).fetchone()

    def _open_jobs(self, target_id: int) -> int:
        return self.conn.execute(
            """SELECT COUNT(*) FROM jobs WHERE state IN ('queued', 'running')
               AND kind = 'triage_file' AND json_extract(payload, '$.target_id') = ?""",
            (target_id,),
        ).fetchone()[0]

    # ------------------------------------------------------------------ steps
    def _step(self, t: sqlite3.Row, summary: RunSummary) -> bool:
        """Advance one stage. Returns True if the target moved and may move again."""
        stage = t["stage"]
        if stage == "new":
            if t["source"] not in ("practice", "backtest"):
                # Real programs need a human-confirmed policy (scope.check). No intel stage yet.
                raise PermissionError("program targets need a confirmed scope policy; none exists yet")
            snap = self.fetcher(t["locator"], t["pinned_ref"], self.cfg.data_dir / "snapshots")
            self._set_stage(t, "fetched", summary, snapshot_path=str(snap.path),
                            pinned_ref=snap.commit, snapshot_hash=snap.content_hash)
            return True
        if stage == "fetched":
            self.compiler(Path(t["snapshot_path"]), self.solc)
            self._set_stage(t, "compiler_ready", summary)
            return True
        if stage == "compiler_ready":
            files = select_files(Path(t["snapshot_path"]), json.loads(t["include_json"] or '["src/**/*.sol"]'))
            if not files:
                raise ValueError("no .sol files matched the target's include globs")
            done = {r["path"] for r in self.conn.execute("SELECT path FROM triage WHERE target_id = ?", (t["id"],))}
            for rel in files:
                if rel not in done:
                    self.queue.enqueue("triage_file", {"target_id": t["id"], "path": rel})
            self._set_stage(t, "triage_queued", summary)
            return False  # wait for the queue
        if stage == "triage_queued":
            if self._open_jobs(t["id"]):
                return False
            n = self.conn.execute("SELECT COUNT(*) FROM triage WHERE target_id = ?", (t["id"],)).fetchone()[0]
            if n == 0:
                raise RuntimeError("every triage job failed; see `bounty queue` / jobs.error")
            self._set_stage(t, "triaged", summary)
            return True
        if stage == "triaged":
            rank_hotspots(self.conn, t["id"])
            self._set_stage(t, "ranked", summary)
            return True
        if stage == "ranked":
            self._set_stage(t, "awaiting_analysis", summary)
            return False
        return False

    def advance_all(self, summary: RunSummary) -> None:
        ids = [r["id"] for r in self.conn.execute(
            f"SELECT id FROM targets WHERE name IS NOT NULL AND stage NOT IN ({','.join('?' * len(TERMINAL))})"
            " ORDER BY id", TERMINAL)]
        for tid in ids:
            if tid in summary.failed_ids:
                continue  # already failed in this run; don't count the same failure twice
            while True:
                t = self._target(tid)
                if t["stage"] in TERMINAL:
                    break
                try:
                    if not self._step(t, summary):
                        break
                except Exception as exc:  # noqa: BLE001 - record and move on to the next target
                    self._fail(t, exc, summary)
                    break

    def drain(self, deadline: float, summary: RunSummary) -> None:
        while True:
            if self.clock() >= deadline:
                if self.queue.counts().get("queued"):
                    summary.out_of_time = True
                return
            if not run_once(self.queue, self.handlers):
                return
            summary.jobs_run += 1

    def _hotspot_analyzed(self, hotspot_id: int) -> bool:
        # A hotspot is done once it has a resolved hypothesis (poc_written or dropped).
        return self.conn.execute(
            "SELECT COUNT(*) FROM hypotheses WHERE hotspot_id = ? AND status != 'open'",
            (hotspot_id,)).fetchone()[0] > 0

    def analyze_all(self, deadline: float, summary: RunSummary) -> None:
        """Stage D: run the analyzer on each awaiting_analysis target's top hotspots.

        Gated by [analysis] enabled, because this is the first stage that spends API money.
        Budget- and deadline-aware: a cap hit stops all analysis (budget is global), the
        clock stops a target mid-way (the next run resumes), any other error fails the target.
        """
        if not self.cfg.analysis.get("enabled", False):
            return
        from bounty_agent.ledger import BudgetExceeded, KillSwitchEngaged
        from bounty_agent.pipeline.analysis import Analyzer

        analyzer = Analyzer(self.cfg, self.conn, self.router)
        top_n = int(self.cfg.analysis.get("top_n", 5))
        ids = [r["id"] for r in self.conn.execute(
            "SELECT id FROM targets WHERE name IS NOT NULL AND stage = 'awaiting_analysis' ORDER BY id")]
        for tid in ids:
            t = self._target(tid)
            hotspots = self.conn.execute(
                "SELECT * FROM hotspots WHERE target_id = ? ORDER BY rank LIMIT ?", (tid, top_n)).fetchall()
            finished = True
            for h in hotspots:
                if self.clock() >= deadline:
                    summary.out_of_time = True
                    return  # stop here; the target stays awaiting_analysis and resumes next run
                if self._hotspot_analyzed(h["id"]):
                    continue
                try:
                    res = analyzer.analyze(t, h)
                except (BudgetExceeded, KillSwitchEngaged) as exc:
                    summary.errors.append(f"analysis stopped (budget/kill): {exc}")
                    return  # the cap is global; don't try other targets
                except Exception as exc:  # noqa: BLE001
                    self._fail(t, exc, summary)
                    finished = False
                    break
                summary.hotspots_analyzed += 1
                if res.passed:
                    summary.findings += 1
            if finished:
                self._set_stage(t, "analyzed", summary)

    def collect_batches(self, summary: RunSummary) -> None:
        if self.batch_runner is not None:
            for bid in self.batch_runner.pending():
                try:
                    if self.batch_runner.collect(bid) is not None:
                        summary.batches_collected += 1
                except Exception as exc:  # noqa: BLE001
                    summary.errors.append(f"batch {bid}: {type(exc).__name__}: {exc}")
        # Results are stored in batch_items, so applying them is separate and re-runnable.
        from bounty_agent.pipeline.skeptic import Skeptic

        try:
            summary.reviews += Skeptic(self.cfg, self.conn, self.router).apply_batches()
        except Exception as exc:  # noqa: BLE001
            summary.errors.append(f"applying skeptic reviews: {type(exc).__name__}: {exc}")

    def review_all(self, deadline: float, summary: RunSummary) -> None:
        """Stage F2: send unreviewed findings to the skeptic. Gated by [review] enabled.

        Batch mode (default) submits one batch; the next run collects it. Sync mode reviews
        each finding now. A budget cap or kill switch stops the stage, never the run."""
        if not self.cfg.review.get("enabled", False):
            return
        from bounty_agent.ledger import BudgetExceeded, KillSwitchEngaged
        from bounty_agent.pipeline.skeptic import Skeptic

        skeptic = Skeptic(self.cfg, self.conn, self.router, self.batch_runner)
        pending = skeptic.pending()
        if not pending:
            return
        try:
            if self.cfg.review.get("mode", "batch") == "batch" and self.batch_runner is not None:
                skeptic.submit_batch(pending)
                summary.advanced.append(f"skeptic: {len(pending)} finding(s) sent as a batch")
                return
            for fid in pending:
                if self.clock() >= deadline:
                    summary.out_of_time = True
                    return
                skeptic.review_now(fid)
                summary.reviews += 1
        except (BudgetExceeded, KillSwitchEngaged) as exc:
            summary.errors.append(f"skeptic stopped (budget/kill): {exc}")
        except Exception as exc:  # noqa: BLE001
            summary.errors.append(f"skeptic: {type(exc).__name__}: {exc}")

    def run(self, max_minutes: float) -> RunSummary:
        deadline = self.clock() + max_minutes * 60
        with run_lock(self.cfg.data_dir / "run.lock"):
            run_id = self.conn.execute("INSERT INTO runs DEFAULT VALUES").lastrowid
            summary = RunSummary(run_id)
            status = "error"
            try:
                self.queue.requeue_stale(older_than_minutes=STALE_JOB_MINUTES)
                self.collect_batches(summary)
                sync_targets(self.conn, load_manifest(self.manifest))
                self.advance_all(summary)
                self.drain(deadline, summary)
                self.advance_all(summary)
                self.analyze_all(deadline, summary)
                self.review_all(deadline, summary)
                status = "ok"
                return summary
            finally:
                self.conn.execute(
                    "UPDATE runs SET finished_at = datetime('now'), status = ?, summary_json = ? WHERE id = ?",
                    (status, json.dumps(summary.as_dict()), run_id),
                )
