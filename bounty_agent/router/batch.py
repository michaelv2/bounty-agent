"""Message Batches API: 50% off for work that can wait up to 24h (SPEC.md §5).

Used for the skeptic review (F2) and report drafting (G). Flow:

    batches = BatchRunner(router)
    batch_id = batches.submit("skeptic_review", [BatchItem("finding-12", system, msgs, target_id=3), ...])
    ...later (e.g. the next pipeline run)...
    results = batches.collect(batch_id)     # None while still processing

Budget: at submit time each item's worst-case cost is checked against the caps and
*reserved* (batch_items.state = 'pending'), so other calls can't spend the same money
while the batch runs. At collect time the actual cost is recorded and the reservation released.
"""

from __future__ import annotations

import re
import uuid
from collections import defaultdict
from contextlib import contextmanager
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Protocol

from bounty_agent.ledger import Usage
from bounty_agent.router.providers import Completion, Message
from bounty_agent.router.router import Router, estimate_cost

CUSTOM_ID = re.compile(r"^[a-zA-Z0-9_-]{1,64}$")  # the API's own rule


class BatchError(RuntimeError):
    pass


@contextmanager
def _tx(conn):
    """One explicit transaction; ROLLBACK on any error so the connection is never left mid-transaction."""
    conn.execute("BEGIN")
    try:
        yield
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    conn.execute("COMMIT")


@dataclass(frozen=True)
class BatchItem:
    custom_id: str
    system: str
    messages: list[Message]
    max_tokens: int = 4096
    target_id: int | None = None
    params: dict = field(default_factory=dict)  # extra request fields, e.g. {"output_config": {...}}


@dataclass(frozen=True)
class BatchResult:
    custom_id: str
    type: str  # succeeded | errored | canceled | expired
    text: str = ""
    usage: Usage = field(default_factory=Usage)
    error: str = ""


class BatchClient(Protocol):
    def create(self, requests: list[dict]) -> str: ...
    def status(self, batch_id: str) -> str: ...
    def results(self, batch_id: str) -> Iterable[BatchResult]: ...


class AnthropicBatchClient:
    """Thin wrapper over client.messages.batches, so the runner can be tested with a fake."""

    def __init__(self, client=None):
        if client is None:
            import anthropic

            client = anthropic.Anthropic()
        self.client = client

    def create(self, requests):
        return self.client.messages.batches.create(requests=requests).id

    def status(self, batch_id):
        return self.client.messages.batches.retrieve(batch_id).processing_status

    def results(self, batch_id):
        for r in self.client.messages.batches.results(batch_id):
            outcome = r.result
            if outcome.type == "succeeded":
                msg = outcome.message
                u = msg.usage
                yield BatchResult(
                    custom_id=r.custom_id,
                    type="succeeded",
                    text="".join(b.text for b in msg.content if getattr(b, "type", None) == "text"),
                    usage=Usage(
                        input_tokens=u.input_tokens or 0,
                        output_tokens=u.output_tokens or 0,
                        cache_read_tokens=getattr(u, "cache_read_input_tokens", 0) or 0,
                        cache_write_tokens=getattr(u, "cache_creation_input_tokens", 0) or 0,
                    ),
                )
            else:
                err = getattr(outcome, "error", None)
                yield BatchResult(custom_id=r.custom_id, type=outcome.type, error=str(err) if err else "")


class BatchRunner:
    def __init__(self, router: Router, client: BatchClient | None = None):
        self.router = router
        self._client = client

    @property
    def client(self) -> BatchClient:
        if self._client is None:
            self._client = AnthropicBatchClient()
        return self._client

    @property
    def conn(self):
        return self.router.ledger.conn

    def submit(self, stage: str, items: list[BatchItem], *, cache: bool = False) -> str:
        route = self.router.resolve(stage)
        if route.local or route.provider != "anthropic":
            raise BatchError(f"stage {stage!r} routes to {route.provider or 'local'}; batches are for Claude routes")
        if not items:
            raise BatchError("empty batch")
        ids = [i.custom_id for i in items]
        bad = [c for c in ids if not CUSTOM_ID.match(c)]
        if bad:
            raise BatchError(f"invalid custom_id(s): {bad}")
        if len(set(ids)) != len(ids):
            raise BatchError("duplicate custom_id in batch")

        estimates = {
            i.custom_id: estimate_cost(route.model, i.system, i.messages, i.max_tokens, cache=cache, batch=True)
            for i in items
        }
        # Raise before anything is sent: the whole batch must fit the monthly/daily caps,
        # and each target's share must fit its per-target cap.
        self.router.guard.check(sum(estimates.values()))
        per_target: dict[int, float] = defaultdict(float)
        for i in items:
            if i.target_id is not None:
                per_target[i.target_id] += estimates[i.custom_id]
        for target_id, est in per_target.items():
            self.router.guard.check(est, target_id=target_id)

        requests = []
        for i in items:
            params = {**i.params, "model": route.model, "max_tokens": i.max_tokens,
                      "system": i.system, "messages": i.messages}
            if cache:
                params["cache_control"] = {"type": "ephemeral"}
            requests.append({"custom_id": i.custom_id, "params": params})

        # Reserve FIRST, under a local id, so the paid API call can never happen without a
        # reservation in the ledger. If create() fails, the reservation is released.
        local_id = f"local_{uuid.uuid4().hex[:24]}"
        with _tx(self.conn):
            self.conn.execute(
                "INSERT INTO batches (id, stage, model, status, created_ts) VALUES (?, ?, ?, 'reserving', ?)",
                (local_id, stage, route.model, self.router.ledger.now_ts()),
            )
            self.conn.executemany(
                "INSERT INTO batch_items (batch_id, custom_id, target_id, estimate_usd) VALUES (?, ?, ?, ?)",
                [(local_id, i.custom_id, i.target_id, estimates[i.custom_id]) for i in items],
            )
        try:
            api_id = self.client.create(requests)
        except BaseException:
            with _tx(self.conn):
                self.conn.execute("DELETE FROM batch_items WHERE batch_id = ?", (local_id,))
                self.conn.execute("DELETE FROM batches WHERE id = ?", (local_id,))
            raise
        # If this write fails the reservation stays in place (status 'reserving'): money is
        # held, never double-spent. The API id goes in the error so it can be recovered.
        try:
            with _tx(self.conn):
                self.conn.execute("UPDATE batches SET api_id = ?, status = 'in_progress' WHERE id = ?",
                                  (api_id, local_id))
        except Exception as exc:
            raise BatchError(f"batch {api_id} was created but not recorded ({exc}); "
                             f"its reservation {local_id} is still held") from exc
        return local_id

    def collect(self, batch_id: str) -> dict[str, Completion] | None:
        """Record costs and return {custom_id: Completion} for succeeded items, or None if not done yet.

        `batch_id` is the local id returned by submit(). Everything is written in one
        transaction: on any error nothing is recorded and the batch can be collected again.
        """
        row = self.conn.execute("SELECT stage, model, status, api_id FROM batches WHERE id = ?",
                                (batch_id,)).fetchone()
        if row is None:
            raise BatchError(f"unknown batch {batch_id!r}")
        if row["status"] == "ended":
            raise BatchError(f"batch {batch_id!r} was already collected")
        if row["status"] != "in_progress" or not row["api_id"]:
            raise BatchError(f"batch {batch_id!r} is {row['status']!r}, not collectable")
        api_id = row["api_id"]
        if self.client.status(api_id) != "ended":
            return None

        targets = {
            r["custom_id"]: r["target_id"]
            for r in self.conn.execute("SELECT custom_id, target_id FROM batch_items WHERE batch_id = ?", (batch_id,))
        }
        done: dict[str, Completion] = {}
        with _tx(self.conn):
            for res in self.client.results(api_id):
                if res.custom_id not in targets:
                    continue  # not ours; never trust unknown IDs
                if res.type == "succeeded":
                    self.router.ledger.record(
                        stage=row["stage"], model=row["model"], usage=res.usage,
                        target_id=targets[res.custom_id], batch=True,
                    )
                    done[res.custom_id] = Completion(text=res.text, model=row["model"], usage=res.usage)
                self.conn.execute(
                    "UPDATE batch_items SET state = ?, result_text = ?, error = ? WHERE batch_id = ? AND custom_id = ?",
                    (res.type, res.text or None, res.error or None, batch_id, res.custom_id),
                )
            # Anything the API didn't return a result for is released (not billed).
            self.conn.execute(
                "UPDATE batch_items SET state = 'expired', error = 'no result returned' "
                "WHERE batch_id = ? AND state = 'pending'",
                (batch_id,),
            )
            self.conn.execute(
                "UPDATE batches SET status = 'ended', ended_ts = ? WHERE id = ?",
                (self.router.ledger.now_ts(), batch_id),
            )
        return done

    def pending(self) -> list[str]:
        return [r["id"] for r in self.conn.execute("SELECT id FROM batches WHERE status = 'in_progress' ORDER BY created_ts")]
