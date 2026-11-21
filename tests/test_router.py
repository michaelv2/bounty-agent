import pytest

from bounty_agent.ledger import BudgetExceeded, KillSwitchEngaged, Usage
from bounty_agent.router import Completion, Router


class FakeProvider:
    def __init__(self, usage=Usage(1000, 200)):
        self.calls = []
        self.usage = usage

    def complete(self, *, model, system, messages, max_tokens, cache):
        self.calls.append({"model": model, "max_tokens": max_tokens, "cache": cache})
        return Completion(text="ok", model=model, usage=self.usage)


@pytest.fixture
def providers():
    return FakeProvider(), FakeProvider()


@pytest.fixture
def router(cfg, ledger, guard, providers):
    claude, local = providers
    return Router(cfg, ledger, guard, claude=claude, local=local)


def msgs(text="hello"):
    return [{"role": "user", "content": text}]


def test_frontier_call_is_recorded(router, providers, ledger):
    claude, _ = providers
    router.complete(stage="deep_analysis", system="s", messages=msgs(), max_tokens=100, target_id=1)
    assert claude.calls[0]["model"] == "claude-opus-5-5"
    # 1000 in * $4/M + 200 out * $20/M
    assert ledger.spent_target(1) == pytest.approx(0.008)


def test_over_budget_call_is_never_sent(router, providers):
    claude, _ = providers
    # Worst case: 200k output tokens * $20/M = $4 > $2 per-target cap
    with pytest.raises(BudgetExceeded):
        router.complete(stage="deep_analysis", system="s", messages=msgs(), max_tokens=200_000, target_id=1)
    assert claude.calls == []


def test_huge_prompt_counts_toward_estimate(router, providers):
    claude, _ = providers
    big = "x" * 3_000_000  # ~1M tokens estimated -> $4 input alone
    with pytest.raises(BudgetExceeded):
        router.complete(stage="deep_analysis", system="s", messages=msgs(big), max_tokens=10, target_id=1)
    assert claude.calls == []


def test_kill_switch_blocks_frontier_but_not_local(router, providers, cfg):
    claude, local = providers
    cfg.kill_switch_path.touch()
    with pytest.raises(KillSwitchEngaged):
        router.complete(stage="deep_analysis", system="s", messages=msgs())
    router.complete(stage="triage", system="s", messages=msgs())
    assert claude.calls == [] and len(local.calls) == 1


def test_local_route_uses_alias_and_costs_nothing(router, providers, ledger):
    _, local = providers
    router.complete(stage="triage", system="s", messages=msgs(), target_id=3)
    assert local.calls[0]["model"] == "qwen-test"
    assert ledger.spent_target(3) == 0


def test_overflow_moves_local_stage_to_haiku(router, providers):
    claude, local = providers
    router.complete(stage="triage", system="s", messages=msgs(), overflow=True)
    assert claude.calls[0]["model"] == "claude-haiku-5-5" and local.calls == []


def test_cache_flag_is_passed_through(router, providers):
    claude, _ = providers
    router.complete(stage="report_draft", system="s", messages=msgs(), max_tokens=100, cache=True)
    assert claude.calls[0]["cache"] is True


def test_unknown_stage_and_alias_are_errors(router):
    with pytest.raises(KeyError, match="No route"):
        router.complete(stage="nonexistent", system="s", messages=msgs())
    with pytest.raises(KeyError, match="alias"):
        router.complete(stage="broken_alias", system="s", messages=msgs())
