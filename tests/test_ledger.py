from datetime import datetime, timezone

import pytest

from bounty_agent.ledger import BudgetExceeded, KillSwitchEngaged, UnknownModelError, Usage, cost_usd


def test_opus_cost():
    # 1M input at $4 + 100k output at $20/M = $4 + $2
    assert cost_usd("claude-opus-5-5", input_tokens=1_000_000, output_tokens=100_000) == pytest.approx(6.0)


def test_cache_and_batch_pricing():
    # cache read $0.20/M, cache write $5/M, then 50% batch discount
    usd = cost_usd("claude-opus-5-5", cache_read_tokens=1_000_000, cache_write_tokens=1_000_000, batch=True)
    assert usd == pytest.approx((0.20 + 5.00) / 2)


def test_haiku_long_context_tier():
    short = cost_usd("claude-haiku-5-5", input_tokens=100_000)
    long = cost_usd("claude-haiku-5-5", input_tokens=100_001)
    assert short == pytest.approx(0.01)
    assert long == pytest.approx(100_001 * 0.50 / 1_000_000)


def test_unknown_model_is_an_error_not_free():
    with pytest.raises(UnknownModelError):
        cost_usd("claude-imaginary-9", input_tokens=1)


def test_local_calls_cost_nothing_but_are_recorded(ledger, conn):
    usd = ledger.record(stage="triage", model="qwen-test", usage=Usage(5000, 500), local=True)
    assert usd == 0
    row = conn.execute("SELECT input_tokens, output_tokens, usd FROM costs").fetchone()
    assert tuple(row) == (5000, 500, 0)


def test_monthly_cap(conn, cfg, clock):
    from bounty_agent.ledger import BudgetGuard, Ledger

    # $8 spent earlier this month (a different day, so the $5 daily cap isn't involved)
    earlier = Ledger(conn, clock=lambda: datetime(2026, 11, 3, 9, 0, tzinfo=timezone.utc))
    earlier.record(stage="x", model="claude-opus-5-5", usage=Usage(input_tokens=2_000_000))
    guard = BudgetGuard(Ledger(conn, clock=clock), cfg.budget, cfg.kill_switch_path)
    guard.check(1.99)  # $9.99 fits under the $10 monthly cap
    with pytest.raises(BudgetExceeded, match="monthly"):
        guard.check(2.01)


def test_month_spend_excludes_previous_month(conn, cfg, clock):
    from bounty_agent.ledger import BudgetGuard, Ledger

    last_month = Ledger(conn, clock=lambda: datetime(2026, 10, 31, 23, 0, tzinfo=timezone.utc))
    last_month.record(stage="x", model="claude-opus-5-5", usage=Usage(input_tokens=2_000_000))  # $8 in October
    now = Ledger(conn, clock=clock)
    assert now.spent_month() == 0
    BudgetGuard(now, cfg.budget, cfg.kill_switch_path).check(4.0)  # fine: October doesn't count


def test_daily_cap(guard, ledger):
    ledger.record(stage="x", model="claude-opus-5-5", usage=Usage(input_tokens=1_000_000))  # $4
    guard.check(0.99)
    with pytest.raises(BudgetExceeded, match="daily"):
        guard.check(1.01)


def test_per_target_cap(guard, ledger):
    ledger.record(stage="x", model="claude-opus-5-5", usage=Usage(input_tokens=400_000), target_id=7)  # $1.60
    guard.check(0.39, target_id=7)
    guard.check(1.0, target_id=8)  # a different target has its own allowance
    with pytest.raises(BudgetExceeded, match="per-target"):
        guard.check(0.41, target_id=7)


def test_kill_switch(guard, cfg):
    cfg.kill_switch_path.touch()
    with pytest.raises(KillSwitchEngaged):
        guard.check(0.0)
