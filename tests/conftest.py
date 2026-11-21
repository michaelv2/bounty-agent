from datetime import datetime, timezone

import pytest

from bounty_agent import db
from bounty_agent.config import BudgetConfig, Config, LocalConfig
from bounty_agent.ledger import BudgetGuard, Ledger


class FixedClock:
    def __init__(self, dt: datetime):
        self.dt = dt

    def __call__(self) -> datetime:
        return self.dt


@pytest.fixture
def conn():
    c = db.connect(":memory:")
    yield c
    c.close()


@pytest.fixture
def clock():
    return FixedClock(datetime(2026, 11, 21, 12, 0, tzinfo=timezone.utc))


@pytest.fixture
def cfg(tmp_path):
    return Config(
        budget=BudgetConfig(monthly_usd=10.0, daily_usd=5.0, per_target_usd=2.0),
        local=LocalConfig(base_url="http://llm.test/v1", aliases={"local-triage": "qwen-test"}),
        routes={
            "triage": "local:local-triage",
            "deep_analysis": "claude-opus-5-5",
            "report_draft": "claude-sonnet-5-5",
            "overflow": "claude-haiku-5-5",
            "broken_alias": "local:nope",
        },
        data_dir=tmp_path,
    )


@pytest.fixture
def ledger(conn, clock):
    return Ledger(conn, clock=clock)


@pytest.fixture
def guard(ledger, cfg):
    return BudgetGuard(ledger, cfg.budget, cfg.kill_switch_path)
