import pytest

from bounty_agent.ledger import BudgetExceeded, Usage
from bounty_agent.router import BatchError, BatchItem, BatchResult, BatchRunner, Router
from tests.test_router import FakeProvider


class FakeBatchClient:
    def __init__(self):
        self.created = []
        self.state = "in_progress"
        self.canned: list[BatchResult] = []

    def create(self, requests):
        self.created.append(requests)
        return f"msgbatch_{len(self.created)}"

    def status(self, batch_id):
        return self.state

    def results(self, batch_id):
        return list(self.canned)


@pytest.fixture
def client():
    return FakeBatchClient()


@pytest.fixture
def runner(cfg, ledger, guard, client):
    cfg.routes["skeptic_review"] = "claude-opus-5-5"
    router = Router(cfg, ledger, guard, claude=FakeProvider(), local=FakeProvider())
    return BatchRunner(router, client)


def item(cid, target_id=None, max_tokens=1000):
    return BatchItem(cid, system="refute this finding", messages=[{"role": "user", "content": "PoC..."}],
                     max_tokens=max_tokens, target_id=target_id)


def test_submit_builds_requests_and_reserves_budget(runner, client, ledger):
    bid = runner.submit("skeptic_review", [item("f-1", target_id=1), item("f-2", target_id=1)], cache=True)
    req = client.created[0]
    assert [r["custom_id"] for r in req] == ["f-1", "f-2"]
    assert req[0]["params"]["model"] == "claude-opus-5-5"
    assert req[0]["params"]["cache_control"] == {"type": "ephemeral"}
    # 1000 output tokens at the batch rate ($10/M) = $0.01 each, plus a tiny prompt estimate
    assert ledger.reserved_target(1) == pytest.approx(0.02, abs=0.001)
    assert ledger.spent_month() == 0  # nothing billed yet
    assert runner.pending() == [bid]


def test_reservations_count_against_caps(runner, guard):
    # Per-target cap is $2: reserve ~$1.50 (150k output tokens at $10/M)
    runner.submit("skeptic_review", [item("big", target_id=5, max_tokens=150_000)])
    with pytest.raises(BudgetExceeded, match="per-target"):
        guard.check(0.60, target_id=5)


def test_over_budget_batch_is_never_sent(runner, client):
    with pytest.raises(BudgetExceeded):
        runner.submit("skeptic_review", [item("huge", target_id=1, max_tokens=500_000)])  # $5 > $2 cap
    assert client.created == []


def test_collect_returns_none_until_ended(runner, client):
    bid = runner.submit("skeptic_review", [item("f-1")])
    assert runner.collect(bid) is None


def test_collect_records_actual_cost_and_releases_reservations(runner, client, ledger, conn):
    bid = runner.submit("skeptic_review", [item("ok", target_id=2), item("bad", target_id=2), item("lost", target_id=2)])
    client.state = "ended"
    client.canned = [
        BatchResult("ok", "succeeded", text='{"verdict": "reject"}', usage=Usage(10_000, 1_000)),
        BatchResult("bad", "errored", error="invalid_request_error"),
        BatchResult("intruder", "succeeded", text="not ours", usage=Usage(1, 1)),
    ]
    done = runner.collect(bid)
    assert set(done) == {"ok"} and done["ok"].text == '{"verdict": "reject"}'
    # Batch price: 10k in * $2/M + 1k out * $10/M = $0.03
    assert ledger.spent_target(2) == pytest.approx(0.03)
    assert ledger.reserved_target(2) == 0
    states = dict(conn.execute("SELECT custom_id, state FROM batch_items").fetchall())
    assert states == {"ok": "succeeded", "bad": "errored", "lost": "expired"}
    assert runner.pending() == []
    with pytest.raises(BatchError, match="already collected"):
        runner.collect(bid)


@pytest.mark.parametrize("ids", [["has space"], ["x" * 65], ["dup", "dup"], []])
def test_invalid_batches_rejected(runner, client, ids):
    with pytest.raises(BatchError):
        runner.submit("skeptic_review", [item(i) for i in ids])
    assert client.created == []


def test_local_stage_cannot_be_batched(runner):
    with pytest.raises(BatchError, match="local"):
        runner.submit("triage", [item("x")])
