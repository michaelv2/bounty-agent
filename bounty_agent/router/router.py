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
    model: str          # Claude model ID, hosted model ID, or the local model behind an alias
    provider: str = ""  # "local" | "anthropic" | a [providers.<name>] entry


def estimate_tokens(text: str) -> int:
    """Conservative token estimate. ASCII at ~3 chars/token; every non-ASCII character is
    charged its UTF-8 byte count (each byte can be its own token), since target content is
    attacker-controlled and emoji/CJK padding would otherwise be badly underestimated."""
    ascii_chars = sum(1 for c in text if ord(c) < 128)
    non_ascii_bytes = len(text.encode("utf-8")) - ascii_chars
    return ascii_chars // CHARS_PER_TOKEN_ESTIMATE + non_ascii_bytes + 1


def estimate_cost(model: str, system: str, messages: list[Message], max_tokens: int,
                  *, cache: bool, batch: bool = False) -> float:
    """Worst case: the whole prompt is a cache write (if caching) and output hits max_tokens."""
    prompt_tokens = estimate_tokens(system) + sum(estimate_tokens(m["content"]) for m in messages)
    return cost_usd(
        model,
        input_tokens=0 if cache else prompt_tokens,
        cache_write_tokens=prompt_tokens if cache else 0,
        output_tokens=max_tokens,
        batch=batch,
    )


class Router:
    def __init__(
        self,
        config: Config,
        ledger: Ledger,
        guard: BudgetGuard,
        *,
        claude: Provider | None = None,
        local: Provider | None = None,
        remote: dict[str, Provider] | None = None,
    ):
        self.config = config
        self.ledger = ledger
        self.guard = guard
        self._claude = claude
        self._local = local
        self._remote: dict[str, Provider] = dict(remote or {})

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

            self._local = LocalProvider(self.config.local.base_url, self.config.local.timeout_s,
                                        reasoning_effort=self.config.local.reasoning_effort)
        return self._local

    def remote(self, name: str) -> Provider:
        if name not in self._remote:
            from bounty_agent.router.providers import OpenAICompatProvider

            pc = self.config.providers[name]
            self._remote[name] = OpenAICompatProvider(pc.base_url, pc.timeout_s, api_key_env=pc.key_env,
                                                      reasoning_effort=pc.reasoning_effort)
        return self._remote[name]

    def resolve(self, stage: str, *, overflow: bool = False) -> Route:
        """Route strings: "local:<alias>" (llm-server, free), "<provider>:<model>" (a hosted
        OpenAI-compatible API from [providers], paid), or a bare Claude model ID (paid)."""
        try:
            target = self.config.routes[stage]
        except KeyError:
            raise KeyError(f"No route for stage {stage!r} in router.toml") from None

        if target.startswith(LOCAL_PREFIX):
            if overflow:
                return self.resolve("overflow")
            alias = target.removeprefix(LOCAL_PREFIX)
            try:
                return Route(stage, local=True, model=self.config.local.aliases[alias], provider="local")
            except KeyError:
                raise KeyError(f"Local alias {alias!r} is not defined in [local.aliases]") from None
        if ":" in target:
            name, model = target.split(":", 1)
            if name not in self.config.providers:
                raise KeyError(f"Provider {name!r} (route for {stage!r}) is not defined in [providers]")
            return Route(stage, local=False, model=model, provider=name)
        return Route(stage, local=False, model=target, provider="anthropic")

    def _provider(self, route: Route) -> Provider:
        if route.provider == "local":
            return self.local
        if route.provider == "anthropic":
            return self.claude
        return self.remote(route.provider)

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

        # Every paid route (Claude or hosted) is estimated, checked and recorded the same way.
        estimate = estimate_cost(route.model, system, messages, max_tokens, cache=cache)
        self.guard.check(estimate, target_id=target_id)  # raises before any API call

        result = self._provider(route).complete(
            model=route.model, system=system, messages=messages, max_tokens=max_tokens, cache=cache
        )
        self.ledger.record(stage=stage, model=route.model, usage=result.usage, target_id=target_id)
        return result
