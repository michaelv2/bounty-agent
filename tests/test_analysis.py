"""Stage D: reply parsing, context safety, and the write->lint->sandbox->feedback loop (fakes only)."""


import pytest

from bounty_agent.pipeline.analysis import (
    POC_CONTRACT,
    POC_TEST,
    AnalysisParseError,
    Analyzer,
    build_context,
    parse_reply,
)
from bounty_agent.router import Completion, Router
from bounty_agent.sandbox import PocResult, RunResult

GOOD_POC = f"""// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;
contract {POC_CONTRACT} {{
    function {POC_TEST}() public {{
        require(2 + 2 == 4, "math");
    }}
}}
"""

GOOD_REPLY = f"""Here is my analysis.
<hypothesis>
title: Reentrancy drains the vault
severity: high
attacker: an unprivileged user
impact: the vault loses all deposits
steps: deposit, then re-enter withdraw before the balance is zeroed
</hypothesis>

```solidity
{GOOD_POC}```
"""


def result(passed, reason="r", stdout="forge json", stderr=""):
    run = RunResult(0 if passed else 1, stdout, stderr, False, 1.0)
    return PocResult(passed, reason, {f"{POC_CONTRACT}.{POC_TEST}()": "Success" if passed else "Failure"}, run=run)


# ------------------------------------------------------------------ parsing

def test_parse_good_reply():
    fields, code = parse_reply(GOOD_REPLY)
    assert fields["title"] == "Reentrancy drains the vault" and fields["severity"] == "high"
    assert f"contract {POC_CONTRACT}" in code and code.endswith("\n")


@pytest.mark.parametrize("reply, msg", [
    ("```solidity\ncontract X {}\n```", "hypothesis"),
    ("<hypothesis>\nseverity: high\n</hypothesis>", "title"),
    ("<hypothesis>\ntitle: t\n</hypothesis>\nno code here", "code block"),
    ("<hypothesis>\ntitle: t\n</hypothesis>\n```solidity\ncontract Wrong {}\n```", "must define"),
])
def test_parse_bad_replies(reply, msg):
    with pytest.raises(AnalysisParseError, match=msg):
        parse_reply(reply)


NOT_EXPLOITABLE = """<hypothesis>
title: Zero fee during grace period
exploitable: no
severity: low
attacker: an unprivileged user
impact: the zero fee is documented intended behavior, nothing is lost
steps: none
</hypothesis>
"""


def test_not_exploitable_needs_no_code_and_ignores_any_sent():
    fields, code = parse_reply(NOT_EXPLOITABLE)
    assert fields["exploitable"] == "no" and code is None
    fields, code = parse_reply(NOT_EXPLOITABLE + f"```solidity\n{GOOD_POC}```")
    assert code is None  # a passing "safe behavior" test must not be run as a PoC


def test_missing_exploitable_line_means_yes_and_requires_code():
    assert parse_reply(GOOD_REPLY)[0]["exploitable"] == "yes"
    with pytest.raises(AnalysisParseError, match="code block"):
        parse_reply("<hypothesis>\ntitle: t\nexploitable: yes\n</hypothesis>")


def test_severity_normalized():
    r = GOOD_REPLY.replace("severity: high", "severity: CRITICAL!!")
    assert parse_reply(r)[0]["severity"] == "low"  # unknown severity is treated as low


# ------------------------------------------------------------------ context safety

@pytest.fixture
def snapshot(tmp_path):
    s = tmp_path / "snap"
    (s / "src").mkdir(parents=True)
    (s / "src" / "Vault.sol").write_text("contract Vault {}")
    (s / "src" / "Token.sol").write_text("contract Token {}")
    return s


def test_build_context_puts_hotspot_first_and_tags_files(snapshot):
    ctx = build_context(snapshot, "src/Vault.sol", ["src/Token.sol", "src/Vault.sol"])
    assert ctx.index('path="src/Vault.sol"') < ctx.index('path="src/Token.sol"')
    assert "<file" in ctx and "</file>" in ctx


def test_build_context_ignores_paths_outside_snapshot(snapshot, tmp_path):
    (tmp_path / "secret").write_text("SECRET")
    (snapshot / "src" / "Link.sol").symlink_to(tmp_path / "secret")
    ctx = build_context(snapshot, "src/Vault.sol", ["src/Link.sol", "../../secret"])
    assert "SECRET" not in ctx


# ------------------------------------------------------------------ the loop

class FakeAnalysisRouter:
    """Returns queued replies for stage deep_analysis; records messages seen."""

    def __init__(self, replies):
        self.replies = list(replies)
        self.seen = []

    def complete(self, *, stage, system, messages, max_tokens, target_id=None, **kw):
        assert stage == "deep_analysis"
        self.seen.append(messages[-1]["content"])
        return Completion(text=self.replies.pop(0), model="fake", usage=__import__("bounty_agent.ledger",
                          fromlist=["Usage"]).Usage(10, 5))


def make_analyzer(cfg, conn, router, poc_results):
    results = iter(poc_results)

    def fake_poc(sandbox_cfg, snapshot, cache, poc_file, *, dest, match_test):
        assert poc_file.read_text().strip()  # the PoC was written to disk
        return next(results)

    return Analyzer(cfg, conn, router, poc_runner=fake_poc)


def seed_target(conn, snapshot):
    tid = conn.execute("INSERT INTO targets (name, source, kind, locator, pinned_ref, snapshot_path, stage) "
                       "VALUES ('t', 'practice', 'repo', 'u', 'r', ?, 'awaiting_analysis')",
                       (str(snapshot),)).lastrowid
    conn.execute("INSERT INTO triage (target_id, path, model, items_json) VALUES (?, 'src/Vault.sol', 'm', '[]')", (tid,))
    hid = conn.execute("INSERT INTO hotspots (target_id, path, rank, rationale, function, confidence) "
                       "VALUES (?, 'src/Vault.sol', 1, 'maybe reentrant', 'withdraw', 'high')", (tid,)).lastrowid
    return conn.execute("SELECT * FROM targets WHERE id = ?", (tid,)).fetchone(), \
        conn.execute("SELECT * FROM hotspots WHERE id = ?", (hid,)).fetchone()


def test_passing_poc_becomes_a_finding(cfg, conn, snapshot):
    cfg.analysis.update({"max_iterations": 3})
    t, h = seed_target(conn, snapshot)
    router = FakeAnalysisRouter([GOOD_REPLY])
    res = make_analyzer(cfg, conn, router, [result(True)]).analyze(t, h)
    assert res.passed and res.iterations == 1 and res.finding_id
    f = conn.execute("SELECT title, severity FROM findings WHERE id = ?", (res.finding_id,)).fetchone()
    assert f["title"] == "Reentrancy drains the vault" and f["severity"] == "high"
    details = conn.execute("SELECT details_json FROM findings WHERE id = ?", (res.finding_id,)).fetchone()[0]
    assert "re-enter withdraw" in details  # the full hypothesis is kept for the skeptic (F2)
    assert conn.execute("SELECT status FROM hypotheses WHERE id = ?", (res.hypothesis_id,)).fetchone()[0] == "poc_written"


def test_failed_poc_feeds_back_then_gives_up(cfg, conn, snapshot):
    cfg.analysis.update({"max_iterations": 2})
    t, h = seed_target(conn, snapshot)
    router = FakeAnalysisRouter([GOOD_REPLY, GOOD_REPLY])
    res = make_analyzer(cfg, conn, router, [result(False, "not all succeeded"), result(False, "still failing")]).analyze(t, h)
    assert not res.passed and res.iterations == 2
    assert "<sandbox_output>" in router.seen[1]  # the failure was fed back for the retry
    assert conn.execute("SELECT status FROM hypotheses WHERE id = ?", (res.hypothesis_id,)).fetchone()[0] == "dropped"
    assert conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == 0


def test_second_attempt_can_pass(cfg, conn, snapshot):
    cfg.analysis.update({"max_iterations": 3})
    t, h = seed_target(conn, snapshot)
    res = make_analyzer(cfg, conn, FakeAnalysisRouter([GOOD_REPLY, GOOD_REPLY]),
                        [result(False), result(True)]).analyze(t, h)
    assert res.passed and res.iterations == 2


def test_cheating_poc_is_rejected_before_the_sandbox(cfg, conn, snapshot):
    cfg.analysis.update({"max_iterations": 1})
    t, h = seed_target(conn, snapshot)
    cheat = GOOD_REPLY.replace('require(2 + 2 == 4, "math");', "vm.store(address(this), bytes32(0), bytes32(uint256(1)));")
    ran = []

    def never(*a, **k):
        ran.append(1)
        return result(True)
    analyzer = Analyzer(cfg, conn, Router.__new__(Router), poc_runner=never)
    analyzer.router = FakeAnalysisRouter([cheat])
    res = analyzer.analyze(t, h)
    assert not res.passed and not ran and "cheat lint" in res.reason  # sandbox never ran


def test_not_exploitable_verdict_is_dropped_without_a_finding(cfg, conn, snapshot):
    """A 'no' with a passing safe-behavior test attached must not become a finding."""
    cfg.analysis.update({"max_iterations": 3})
    t, h = seed_target(conn, snapshot)
    ran = []

    def never(*a, **k):
        ran.append(1)
        return result(True)
    analyzer = Analyzer(cfg, conn, Router.__new__(Router), poc_runner=never)
    analyzer.router = FakeAnalysisRouter([NOT_EXPLOITABLE + f"```solidity\n{GOOD_POC}```"])
    res = analyzer.analyze(t, h)
    assert not res.passed and res.iterations == 1 and not ran
    assert "not exploitable" in res.reason
    row = conn.execute("SELECT status, summary FROM hypotheses WHERE id = ?", (res.hypothesis_id,)).fetchone()
    assert row["status"] == "dropped" and "intended behavior" in row["summary"]
    assert conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == 0


def test_unparseable_reply_is_fed_back(cfg, conn, snapshot):
    cfg.analysis.update({"max_iterations": 2})
    t, h = seed_target(conn, snapshot)
    router = FakeAnalysisRouter(["I can't help with that.", GOOD_REPLY])
    res = make_analyzer(cfg, conn, router, [result(True)]).analyze(t, h)
    assert res.passed and res.iterations == 2
    assert "required format" in router.seen[1]
