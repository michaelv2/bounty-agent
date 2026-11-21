"""Cost ledger and hard budget caps (SPEC.md §3 rule 7).

Every frontier-model call goes through `BudgetGuard.check()` *before* it is sent,
using a worst-case estimate, and through `Ledger.record()` after it returns.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from bounty_agent.config import BudgetConfig
from bounty_agent.ledger.pricing import cost_usd

Clock = Callable[[], datetime]


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class BudgetExceeded(RuntimeError):
    """A call would push spend past a cap. The call must not be made."""


class KillSwitchEngaged(RuntimeError):
    """The kill-switch file exists. No frontier calls until it is removed."""


@dataclass(frozen=True)
class Usage:
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0


class Ledger:
    def __init__(self, conn: sqlite3.Connection, clock: Clock = utcnow):
        self.conn = conn
        self.clock = clock

    def record(
        self,
        *,
        stage: str,
        model: str,
        usage: Usage,
        target_id: int | None = None,
        batch: bool = False,
        local: bool = False,
    ) -> float:
        """Store one call. Local-model calls are recorded at $0 so token volume is still tracked."""
        usd = 0.0 if local else cost_usd(
            model,
            input_tokens=usage.input_tokens,
            output_tokens=usage.output_tokens,
            cache_read_tokens=usage.cache_read_tokens,
            cache_write_tokens=usage.cache_write_tokens,
            batch=batch,
        )
        self.conn.execute(
            """INSERT INTO costs (ts, stage, model, target_id, input_tokens, output_tokens,
                                  cache_read_tokens, cache_write_tokens, batch, usd)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                self.clock().strftime("%Y-%m-%d %H:%M:%S"), stage, model, target_id,
                usage.input_tokens, usage.output_tokens,
                usage.cache_read_tokens, usage.cache_write_tokens, int(batch), usd,
            ),
        )
        return usd

    def _sum(self, where: str, params: tuple) -> float:
        row = self.conn.execute(f"SELECT COALESCE(SUM(usd), 0) FROM costs WHERE {where}", params).fetchone()
        return float(row[0])

    def spent_month(self) -> float:
        return self._sum("ts LIKE ?", (self.clock().strftime("%Y-%m-") + "%",))

    def spent_day(self) -> float:
        return self._sum("ts LIKE ?", (self.clock().strftime("%Y-%m-%d") + "%",))

    def spent_target(self, target_id: int) -> float:
        return self._sum("target_id = ?", (target_id,))


class BudgetGuard:
    def __init__(self, ledger: Ledger, budget: BudgetConfig, kill_switch_path: Path):
        self.ledger = ledger
        self.budget = budget
        self.kill_switch_path = kill_switch_path

    def check(self, estimate_usd: float, target_id: int | None = None) -> None:
        """Raise unless `estimate_usd` more spend fits under every cap."""
        if self.kill_switch_path.exists():
            raise KillSwitchEngaged(f"Kill switch present: {self.kill_switch_path}")

        caps = [
            ("monthly", self.ledger.spent_month(), self.budget.monthly_usd),
            ("daily", self.ledger.spent_day(), self.budget.daily_usd),
        ]
        if target_id is not None:
            caps.append(("per-target", self.ledger.spent_target(target_id), self.budget.per_target_usd))

        for name, spent, cap in caps:
            if spent + estimate_usd > cap:
                raise BudgetExceeded(
                    f"{name} cap: spent ${spent:.2f} + estimate ${estimate_usd:.2f} > cap ${cap:.2f}"
                )
