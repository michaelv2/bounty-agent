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
        )


class LocalProvider:
    """Any OpenAI-compatible /v1/chat/completions server (Ollama, vLLM, ...) on llm-server."""

    def __init__(self, base_url: str, timeout_s: float = 600, client: httpx2.Client | None = None):
        self.base_url = base_url.rstrip("/")
        self.client = client or httpx2.Client(timeout=timeout_s)

    def complete(self, *, model, system, messages, max_tokens, cache):
        body = {
            "model": model,
            "messages": [{"role": "system", "content": system}, *messages],
            "max_tokens": max_tokens,
            "stream": False,
        }
        resp = self.client.post(f"{self.base_url}/chat/completions", json=body)
        resp.raise_for_status()
        data = resp.json()
        usage = data.get("usage") or {}
        return Completion(
            text=data["choices"][0]["message"]["content"],
            model=model,
            usage=Usage(
                input_tokens=usage.get("prompt_tokens", 0),
                output_tokens=usage.get("completion_tokens", 0),
            ),
        )

    def list_models(self) -> list[str]:
        resp = self.client.get(f"{self.base_url}/models")
        resp.raise_for_status()
        return [m["id"] for m in resp.json().get("data", [])]
