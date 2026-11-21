"""Stage -> model routing with budget enforcement (SPEC.md §5).

    router.complete(stage="deep_analysis", system=..., messages=[...], target_id=42)

For a Claude route the router:
  1. estimates the worst-case cost (full max_tokens of output),
  2. asks BudgetGuard, which raises *before* any API call if a cap would be exceeded,
  3. makes the call and records the actual cost in the ledger.
Local routes cost $0, but their token counts are still recorded.
"""

from __future__ import annotations

from dataclasses import dataclass

from bounty_agent.config import Config
from bounty_agent.ledger import BudgetGuard, Ledger, cost_usd
from bounty_agent.router.providers import Completion, Message, Provider

LOCAL_PREFIX = "local:"
CHARS_PER_TOKEN_ESTIMATE = 3  # conservative: real ratio is usually ~3.5-4 chars/token


@dataclass(frozen=True)
class Route:
    stage: str
    local: bool
    model: str  # Claude model ID, or the concrete local model name behind an alias


def estimate_tokens(text: str) -> int:
    return len(text) // CHARS_PER_TOKEN_ESTIMATE + 1


class Router:
    def __init__(
        self,
        config: Config,
        ledger: Ledger,
        guard: BudgetGuard,
        *,
        claude: Provider | None = None,
        local: Provider | None = None,
    ):
        self.config = config
        self.ledger = ledger
        self.guard = guard
        self._claude = claude
        self._local = local

    # Providers are created lazily, so a local-only run never needs an API key.
    @property
    def claude(self) -> Provider:
        if self._claude is None:
            from bounty_agent.router.providers import AnthropicProvider

            self._claude = AnthropicProvider()
        return self._claude

    @property
    def local(self) -> Provider:
        if self._local is None:
            from bounty_agent.router.providers import LocalProvider

            self._local = LocalProvider(self.config.local.base_url, self.config.local.timeout_s)
        return self._local

    def resolve(self, stage: str, *, overflow: bool = False) -> Route:
        try:
            target = self.config.routes[stage]
        except KeyError:
            raise KeyError(f"No route for stage {stage!r} in router.toml") from None

        if target.startswith(LOCAL_PREFIX):
            if overflow:
                return self.resolve("overflow")
            alias = target.removeprefix(LOCAL_PREFIX)
            try:
                return Route(stage, local=True, model=self.config.local.aliases[alias])
            except KeyError:
                raise KeyError(f"Local alias {alias!r} is not defined in [local.aliases]") from None
        return Route(stage, local=False, model=target)

    def complete(
        self,
        *,
        stage: str,
        system: str,
        messages: list[Message],
        max_tokens: int = 4096,
        target_id: int | None = None,
        cache: bool = False,
        overflow: bool = False,
    ) -> Completion:
        route = self.resolve(stage, overflow=overflow)

        if route.local:
            result = self.local.complete(
                model=route.model, system=system, messages=messages, max_tokens=max_tokens, cache=False
            )
            self.ledger.record(stage=stage, model=route.model, usage=result.usage, target_id=target_id, local=True)
            return result

        prompt_tokens = estimate_tokens(system) + sum(estimate_tokens(m["content"]) for m in messages)
        # Worst case: the whole prompt is a cache write (if caching) and output hits max_tokens.
        estimate = cost_usd(
            route.model,
            input_tokens=0 if cache else prompt_tokens,
            cache_write_tokens=prompt_tokens if cache else 0,
            output_tokens=max_tokens,
        )
        self.guard.check(estimate, target_id=target_id)  # raises before any API call

        result = self.claude.complete(
            model=route.model, system=system, messages=messages, max_tokens=max_tokens, cache=cache
        )
        self.ledger.record(stage=stage, model=route.model, usage=result.usage, target_id=target_id)
        return result
