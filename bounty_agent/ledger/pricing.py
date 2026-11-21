"""Claude API prices in USD per million tokens.

Sources: https://platform.claude.com/docs/en/about-claude/pricing (checked 2026-11-21);
Mistral-hosted models: docs.mistral.ai/models/pricing via llm-council/VERIFIED.md.
Update this table when prices change. An unknown model raises an error instead of
silently costing $0, so a new model can never slip past the budget caps.
"""

from __future__ import annotations

from dataclasses import dataclass

BATCH_DISCOUNT = 0.5  # Batch API: 50% off input and output; stacks with caching


@dataclass(frozen=True)
class Price:
    input: float
    output: float
    cache_write: float  # 5-minute cache write
    cache_read: float
    # Some models charge more once the whole prompt exceeds a threshold.
    long_threshold: int | None = None
    long_multiplier: float = 1.0


PRICES: dict[str, Price] = {
    "claude-opus-5-5": Price(input=4.00, output=20.00, cache_write=5.00, cache_read=0.20),
    "claude-sonnet-5-5": Price(input=2.00, output=10.00, cache_write=2.50, cache_read=0.10),
    # Hosted on Mistral's API (prices from llm-council/VERIFIED.md, Mistral pricing page, 2026-11).
    # No separate cache-write charge on Mistral; cached input is billed at the cache_read rate.
    "deepseek-v4-1-flash-1017": Price(input=0.30, output=1.20, cache_write=0.30, cache_read=0.007),
    "mistral-large-4": Price(input=0.70, output=2.10, cache_write=0.70, cache_read=0.07),
    # Haiku 5.5: prompts over 100k tokens cost 5x ($0.50 / $2.50 instead of $0.10 / $0.50).
    "claude-haiku-5-5": Price(
        input=0.10, output=0.50, cache_write=0.125, cache_read=0.01,
        long_threshold=100_000, long_multiplier=5.0,
    ),
}


class UnknownModelError(KeyError):
    pass


def price_for(model: str) -> Price:
    try:
        return PRICES[model]
    except KeyError:
        raise UnknownModelError(
            f"No price for model {model!r}. Add it to bounty_agent/ledger/pricing.py."
        ) from None


def cost_usd(
    model: str,
    *,
    input_tokens: int = 0,
    output_tokens: int = 0,
    cache_read_tokens: int = 0,
    cache_write_tokens: int = 0,
    batch: bool = False,
) -> float:
    """Dollar cost of one request. `input_tokens` excludes cached tokens, as the API reports it."""
    p = price_for(model)
    mult = 1.0
    prompt_tokens = input_tokens + cache_read_tokens + cache_write_tokens
    if p.long_threshold is not None and prompt_tokens > p.long_threshold:
        mult = p.long_multiplier
    usd = (
        input_tokens * p.input
        + output_tokens * p.output
        + cache_read_tokens * p.cache_read
        + cache_write_tokens * p.cache_write
    ) * mult / 1_000_000
    if batch:
        usd *= BATCH_DISCOUNT
    return usd
