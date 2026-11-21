"""`bounty run` controller: state machine, resumability, failures, lock, triage and digest.

Fetching, compiling and the local model are faked, so this runs offline in milliseconds.
"""

import json

import pytest

from bounty_agent.fetch import Snapshot
from bounty_agent.ledger import Usage
from bounty_agent.pipeline import AlreadyRunning, ManifestError, Pipeline, build_digest, load_manifest
from bounty_agent.pipeline.controller import MAX_FAILURES, run_lock
from bounty_agent.pipeline.triage import (
    TriageError,
    parse_hotspots,
    rank_hotspots,
    safe_source_path,
    select_files,
)
from bounty_agent.router import Completion, Router

GOOD_REPLY = json.dumps([
    {"function": "flashLoan", "issue": "donation breaks share accounting", "confidence": "high"},
    {"function": "execute", "issue": "owner delegatecall", "confidence": "low"},
])

MANIFEST = """
[[target]]
name = "dvd-unstoppable"
source = "practice"
url = "https://github.com/theredguild/damn-vulnerable-defi"
ref = "64fddf9f96de2782f8868898d68673acb295119c"
include = ["src/unstoppable/*.sol"]
"""


class FakeLocal:
    def __init__(self, reply=GOOD_REPLY):
        self.reply = reply
        self.calls = 0

    def complete(self, *, model, system, messages, max_tokens, cache):
        self.calls += 1
        if isinstance(self.reply, Exception):
            raise self.reply
        return Completion(text=self.reply, model=model, usage=Usage(100, 50))


@pytest.fixture
def snapshot_tree(tmp_path):
    root = tmp_path / "snaps" / "damn-vulnerable-defi-64fddf9f96de"
    (root / "src" / "unstoppable").mkdir(parents=True)
    (root / "src" / "unstoppable" / "UnstoppableVault.sol").write_text("pragma solidity =0.8.25; contract V {}")
    (root / "src" / "unstoppable" / "UnstoppableMonitor.sol").write_text("pragma solidity =0.8.25; contract M {}")
    (root / "src" / "Other.sol").write_text("contract O {}")
    return root


@pytest.fixture
def manifest(tmp_path):
    p = tmp_path / "targets.toml"
    p.write_text(MANIFEST)
    return p


@pytest.fixture
def fakes(snapshot_tree):
    calls = {"fetch": 0, "compile": 0}

    def fetcher(url, ref, snapshots_dir):
        calls["fetch"] += 1
        return Snapshot(snapshot_tree, url, "64fddf9f96de2782f8868898d68673acb295119c", "hash123")

    def compiler(snapshot, cache):
        calls["compile"] += 1
        return {"0.8.25"}

    return fetcher, compiler, calls


def make_pipeline(cfg, conn, ledger, guard, manifest, fakes, local=None, clock=None):
    cfg.routes.setdefault("triage", "local:local-triage")
    fetcher, compiler, _ = fakes
    router = Router(cfg, ledger, guard, local=local or FakeLocal())
    kwargs = {"clock": clock} if clock else {}
    return Pipeline(cfg, conn, router, manifest=manifest, fetcher=fetcher, compiler=compiler, **kwargs)


def target(conn, name="dvd-unstoppable"):
    return conn.execute("SELECT * FROM targets WHERE name = ?", (name,)).fetchone()


# ------------------------------------------------------------------ state machine

def test_full_run_reaches_awaiting_analysis(cfg, conn, ledger, guard, manifest, fakes):
    local = FakeLocal()
    s = make_pipeline(cfg, conn, ledger, guard, manifest, fakes, local).run(max_minutes=10)
    t = target(conn)
    assert t["stage"] == "awaiting_analysis" and not s.errors
    assert t["pinned_ref"] == "64fddf9f96de2782f8868898d68673acb295119c" and t["snapshot_hash"] == "hash123"
    assert local.calls == 2 and s.jobs_run == 2  # only the two include-matched files were triaged
    hot = conn.execute("SELECT rank, function, confidence FROM hotspots ORDER BY rank").fetchall()
    assert [tuple(h) for h in hot][0] == (1, "flashLoan", "high")
    assert conn.execute("SELECT status FROM runs").fetchone()["status"] == "ok"


def test_out_of_time_resumes_next_run(cfg, conn, ledger, guard, manifest, fakes):
    ticks = iter([0, 10_000, 10_000, 10_000])  # deadline already passed when draining starts
    p = make_pipeline(cfg, conn, ledger, guard, manifest, fakes, clock=lambda: next(ticks, 10_000))
    s = p.run(max_minutes=1)
    assert s.out_of_time and target(conn)["stage"] == "triage_queued"
    s2 = make_pipeline(cfg, conn, ledger, guard, manifest, fakes).run(max_minutes=10)
    assert target(conn)["stage"] == "awaiting_analysis" and s2.jobs_run == 2
    _, _, calls = fakes
    assert calls["fetch"] == 1  # not refetched on the second run


def test_rerun_is_idempotent(cfg, conn, ledger, guard, manifest, fakes):
    local = FakeLocal()
    make_pipeline(cfg, conn, ledger, guard, manifest, fakes, local).run(max_minutes=10)
    s = make_pipeline(cfg, conn, ledger, guard, manifest, fakes, local).run(max_minutes=10)
    assert local.calls == 2 and s.jobs_run == 0 and not s.advanced  # nothing redone


def test_failing_step_records_error_then_blocks(cfg, conn, ledger, guard, manifest, fakes):
    fetcher, _, calls = fakes

    def broken_compiler(snapshot, cache):
        raise RuntimeError("solc checksum mismatch")
    for i in range(MAX_FAILURES):
        p = make_pipeline(cfg, conn, ledger, guard, manifest, (fetcher, broken_compiler, calls))
        s = p.run(max_minutes=1)
        assert any("checksum mismatch" in e for e in s.errors)
    t = target(conn)
    assert t["stage"] == "blocked" and t["failures"] == MAX_FAILURES and "checksum" in t["stage_error"]


def test_bad_model_output_retries_then_target_errors(cfg, conn, ledger, guard, manifest, fakes):
    local = FakeLocal(reply="I think the vault is fine!")  # no JSON array
    s = make_pipeline(cfg, conn, ledger, guard, manifest, fakes, local).run(max_minutes=10)
    assert local.calls == 6  # 2 files x 3 attempts
    assert target(conn)["stage"] == "triage_queued" and any("every triage job failed" in e for e in s.errors)


def test_program_targets_refused_without_policy(cfg, conn, ledger, guard, tmp_path, fakes):
    m = tmp_path / "t.toml"
    m.write_text(MANIFEST.replace('source = "practice"', 'source = "program"'))
    s = make_pipeline(cfg, conn, ledger, guard, m, fakes).run(max_minutes=1)
    _, _, calls = fakes
    assert calls["fetch"] == 0 and any("scope policy" in e for e in s.errors)
    assert target(conn)["stage"] == "new"


def test_concurrent_runs_are_refused(cfg, conn, ledger, guard, manifest, fakes):
    with run_lock(cfg.data_dir / "run.lock"):
        with pytest.raises(AlreadyRunning):
            make_pipeline(cfg, conn, ledger, guard, manifest, fakes).run(max_minutes=1)


def test_changing_the_repo_restarts_the_target(cfg, conn, ledger, guard, manifest, fakes):
    make_pipeline(cfg, conn, ledger, guard, manifest, fakes).run(max_minutes=10)
    manifest.write_text(MANIFEST.replace("theredguild/damn-vulnerable-defi", "someone/other-ctf"))
    from bounty_agent.pipeline import sync_targets
    sync_targets(conn, load_manifest(manifest))
    t = target(conn)
    assert t["stage"] == "new" and t["snapshot_path"] is None


# ------------------------------------------------------------------ manifest

@pytest.mark.parametrize("bad", [
    MANIFEST.replace('name = "dvd-unstoppable"', 'name = "Bad Name"'),
    MANIFEST.replace('source = "practice"', 'source = "live"'),
    MANIFEST.replace("https://github.com/theredguild/damn-vulnerable-defi", "file:///etc"),
    MANIFEST.replace('["src/unstoppable/*.sol"]', '["../../etc/*"]'),
    MANIFEST + MANIFEST,  # duplicate name
])
def test_bad_manifests_rejected(tmp_path, bad):
    p = tmp_path / "t.toml"
    p.write_text(bad)
    with pytest.raises(ManifestError):
        load_manifest(p)


# ------------------------------------------------------------------ triage parsing + file safety

def test_parse_hotspots_tolerates_fences_and_normalizes():
    text = "Sure!\n```json\n" + json.dumps([{"function": "f", "issue": "x" * 5000, "confidence": "CRITICAL"}]) + "\n```"
    items = parse_hotspots(text)
    assert items == [{"function": "f", "issue": "x" * 1000, "confidence": "low"}]
    assert parse_hotspots("[]") == []
    for bad in ["nothing here", "[not json", '{"a": 1}']:
        with pytest.raises(TriageError):
            parse_hotspots(bad)


def test_select_files_skips_lib_symlinks_and_non_sol(snapshot_tree, tmp_path):
    (snapshot_tree / "lib" / "oz").mkdir(parents=True)
    (snapshot_tree / "lib" / "oz" / "ERC20.sol").write_text("contract E {}")
    (snapshot_tree / "src" / "unstoppable" / "README.md").write_text("hi")
    outside = tmp_path / "secret.sol"
    outside.write_text("secret")
    (snapshot_tree / "src" / "unstoppable" / "Link.sol").symlink_to(outside)
    assert select_files(snapshot_tree, ["src/**/*.sol", "lib/**/*.sol"]) == [
        "src/Other.sol", "src/unstoppable/UnstoppableMonitor.sol", "src/unstoppable/UnstoppableVault.sol"]


@pytest.mark.parametrize("rel", ["../outside.sol", "/etc/passwd", "src/unstoppable/Link.sol", "src/missing.sol"])
def test_triage_never_reads_outside_the_snapshot(snapshot_tree, tmp_path, rel):
    (tmp_path / "outside.sol").write_text("secret")
    (snapshot_tree / "src" / "unstoppable" / "Link.sol").symlink_to(tmp_path / "outside.sol")
    with pytest.raises(TriageError):
        safe_source_path(snapshot_tree, rel)


def test_ranking_orders_by_confidence(conn):
    conn.execute("INSERT INTO targets (id, kind, locator, pinned_ref) VALUES (1, 'repo', 'u', 'r')")
    conn.execute("INSERT INTO triage (target_id, path, model, items_json) VALUES (1, 'a.sol', 'm', ?)",
                 (json.dumps([{"function": "lo", "issue": "i", "confidence": "low"}]),))
    conn.execute("INSERT INTO triage (target_id, path, model, items_json) VALUES (1, 'b.sol', 'm', ?)",
                 (json.dumps([{"function": "hi", "issue": "i", "confidence": "high"}]),))
    assert rank_hotspots(conn, 1, top_k=1) == 1
    assert conn.execute("SELECT function FROM hotspots").fetchall()[0]["function"] == "hi"


# ------------------------------------------------------------------ digest

def test_digest_reports_budget_targets_and_hotspots(cfg, conn, ledger, guard, manifest, fakes):
    make_pipeline(cfg, conn, ledger, guard, manifest, fakes).run(max_minutes=10)
    md, short = build_digest(cfg, conn)
    for section in ["## Budget", "## Runs", "## Targets", "## Top hotspots", "## Awaiting your review", "## Local queue"]:
        assert section in md
    assert "dvd-unstoppable" in md and "flashLoan" in md and "awaiting_analysis" in md
    assert "awaiting_analysis=1" in short and "\n" not in short


def test_digest_flattens_untrusted_model_text(cfg, conn, ledger, guard, manifest, fakes):
    hostile = json.dumps([{"function": "f", "issue": "line1\n## Fake section\n| injected | table |", "confidence": "high"}])
    make_pipeline(cfg, conn, ledger, guard, manifest, fakes, FakeLocal(hostile)).run(max_minutes=10)
    md, _ = build_digest(cfg, conn)
    assert "\n## Fake section" not in md and "\\| injected" in md


# ---- stage D wired into the controller ----

def test_analysis_is_skipped_unless_enabled(cfg, conn, ledger, guard, manifest, fakes):
    make_pipeline(cfg, conn, ledger, guard, manifest, fakes).run(max_minutes=10)
    assert target(conn)["stage"] == "awaiting_analysis"  # enabled defaults off


def test_enabled_analysis_runs_and_marks_analyzed(cfg, conn, ledger, guard, manifest, fakes, monkeypatch):
    # Reach awaiting_analysis with analysis OFF, then enable it with the Analyzer patched.
    make_pipeline(cfg, conn, ledger, guard, manifest, fakes).run(max_minutes=10)
    assert target(conn)["stage"] == "awaiting_analysis"
    calls = []

    class FakeAnalyzer:
        def __init__(self, *a, **k):
            pass

        def analyze(self, t, h):
            calls.append(h["id"])
            from bounty_agent.pipeline.analysis import AnalysisResult
            conn.execute("INSERT INTO hypotheses (hotspot_id, summary, status) VALUES (?, 'x', 'poc_written')", (h["id"],))
            return AnalysisResult(True, 1, "passed", finding_id=None, hypothesis_id=None)

    monkeypatch.setattr("bounty_agent.pipeline.analysis.Analyzer", FakeAnalyzer)
    cfg.analysis.update({"enabled": True, "top_n": 2, "max_iterations": 1})
    s = make_pipeline(cfg, conn, ledger, guard, manifest, fakes).run(max_minutes=10)
    assert target(conn)["stage"] == "analyzed" and s.findings == 2 and len(calls) == 2  # two ranked hotspots


def test_budget_exceeded_stops_analysis_without_blocking_target(cfg, conn, ledger, guard, manifest, fakes, monkeypatch):
    make_pipeline(cfg, conn, ledger, guard, manifest, fakes).run(max_minutes=10)
    tid = target(conn)["id"]

    class BrokeAnalyzer:
        def __init__(self, *a, **k):
            pass

        def analyze(self, t, h):
            from bounty_agent.ledger import BudgetExceeded
            raise BudgetExceeded("monthly cap")

    monkeypatch.setattr("bounty_agent.pipeline.analysis.Analyzer", BrokeAnalyzer)
    cfg.analysis.update({"enabled": True, "top_n": 2, "max_iterations": 1})
    s = make_pipeline(cfg, conn, ledger, guard, manifest, fakes).run(max_minutes=10)
    t = target(conn)
    assert t["stage"] == "awaiting_analysis" and t["failures"] == 0  # not blocked; resumes when budget frees
    assert any("budget/kill" in e for e in s.errors)
