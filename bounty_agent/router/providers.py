"""Model providers: Claude (Anthropic SDK) and the local OpenAI-compatible endpoint.

Stage code never uses these directly. It goes through `Router`, so budget caps and
the cost ledger always apply.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

import httpx2  # the httpx successor that the anthropic SDK also uses, so there's one HTTP stack

from bounty_agent.ledger import Usage

Message = dict[str, str]  # {"role": "user" | "assistant", "content": "..."}


@dataclass(frozen=True)
class Completion:
    text: str
    model: str
    usage: Usage
    stop_reason: str | None = None  # e.g. "stop"/"end_turn", or "length"/"max_tokens" if truncated
    reasoning: str = ""             # a reasoning model's thinking, kept apart from the answer


class TruncatedOutput(RuntimeError):
    """The model hit max_tokens before producing any answer (e.g. it spent the budget thinking)."""


class Provider(Protocol):
    def complete(
        self, *, model: str, system: str, messages: list[Message], max_tokens: int, cache: bool
    ) -> Completion: ...


class AnthropicProvider:
    """Claude via the official SDK. Reads ANTHROPIC_API_KEY from the environment."""

    def __init__(self, client=None):
        if client is None:
            import anthropic  # imported lazily so tests and local-only runs don't need a key

            client = anthropic.Anthropic()
        self.client = client

    def complete(self, *, model, system, messages, max_tokens, cache):
        kwargs = {"model": model, "max_tokens": max_tokens, "system": system, "messages": messages}
        if cache:
            # Automatic prompt caching: caches everything up to the last cacheable block.
            kwargs["cache_control"] = {"type": "ephemeral"}
        resp = self.client.messages.create(**kwargs)
        text = "".join(b.text for b in resp.content if getattr(b, "type", None) == "text")
        u = resp.usage
        return Completion(
            text=text,
            model=model,
            usage=Usage(
                input_tokens=u.input_tokens or 0,
                output_tokens=u.output_tokens or 0,
                cache_read_tokens=getattr(u, "cache_read_input_tokens", 0) or 0,
                cache_write_tokens=getattr(u, "cache_creation_input_tokens", 0) or 0,
            ),
            stop_reason=getattr(resp, "stop_reason", None),
        )


class LocalProvider:
    """Any OpenAI-compatible /v1/chat/completions server (Ollama, vLLM, ...) on llm-server."""

    def __init__(self, base_url: str, timeout_s: float = 600, client: httpx2.Client | None = None,
                 reasoning_effort: str | None = None):
        self.base_url = base_url.rstrip("/")
        self.client = client or httpx2.Client(timeout=timeout_s)
        # OpenAI-style knob for reasoning models ("none" | "low" | "medium" | "high").
        # Ollama honors it on /v1; servers that don't know it ignore it.
        self.reasoning_effort = reasoning_effort

    def complete(self, *, model, system, messages, max_tokens, cache):
        body = {
            "model": model,
            "messages": [{"role": "system", "content": system}, *messages],
            "max_tokens": max_tokens,
            "stream": False,
        }
        if self.reasoning_effort:
            body["reasoning_effort"] = self.reasoning_effort
        resp = self.client.post(f"{self.base_url}/chat/completions", json=body)
        resp.raise_for_status()
        data = resp.json()
        choice = data["choices"][0]
        msg = choice["message"]
        usage = data.get("usage") or {}
        text = msg.get("content") or ""
        finish = choice.get("finish_reason")
        if not text.strip() and finish == "length":
            raise TruncatedOutput(
                f"{model} used all {max_tokens} output tokens without answering "
                f"(reasoning: {len(msg.get('reasoning') or '')} chars). Raise max_tokens or lower reasoning_effort."
            )
        return Completion(
            text=text,
            model=model,
            usage=Usage(
                input_tokens=usage.get("prompt_tokens", 0),
                output_tokens=usage.get("completion_tokens", 0),
            ),
            stop_reason=finish,
            reasoning=msg.get("reasoning") or msg.get("reasoning_content") or "",
        )

    def list_models(self) -> list[str]:
        resp = self.client.get(f"{self.base_url}/models")
        resp.raise_for_status()
        return [m["id"] for m in resp.json().get("data", [])]
