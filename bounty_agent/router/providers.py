"""Model providers: Claude (Anthropic SDK) and the local OpenAI-compatible endpoint.

Stage code never uses these directly. It goes through `Router`, so budget caps and
the cost ledger always apply.
"""

from __future__ import annotations

import os
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


def message_content(msg: dict) -> tuple[str, str]:
    """(answer text, reasoning text) from an OpenAI-style message.

    `content` is usually a string, but Mistral's reasoning models return a list of typed
    parts: [{"type": "thinking", "thinking": [{"type": "text", "text": ...}]},
    {"type": "text", "text": ...}] (found by llm-council's live tests). Ollama puts
    reasoning in a separate `reasoning` field instead.
    """
    content = msg.get("content")
    reasoning = msg.get("reasoning") or msg.get("reasoning_content") or ""
    if content is None:
        return "", reasoning
    if isinstance(content, str):
        return content, reasoning
    if isinstance(content, list):
        texts, thoughts = [], []
        for part in content:
            if not isinstance(part, dict):
                continue
            if part.get("type") == "text":
                texts.append(str(part.get("text", "")))
            elif part.get("type") == "thinking":
                blocks = part.get("thinking")
                for b in blocks if isinstance(blocks, list) else []:
                    if isinstance(b, dict) and b.get("type") == "text":
                        thoughts.append(str(b.get("text", "")))
        return "".join(texts), reasoning or "".join(thoughts)
    return str(content), reasoning


class MissingAPIKey(RuntimeError):
    pass


class OpenAICompatProvider:
    """Any OpenAI-compatible /v1/chat/completions API: llm-server (Ollama/vLLM, no key) or a
    hosted API such as Mistral's (key read from an env var at call time, never logged)."""

    def __init__(self, base_url: str, timeout_s: float = 600, client: httpx2.Client | None = None,
                 reasoning_effort: str | None = None, api_key_env: str | None = None):
        self.base_url = base_url.rstrip("/")
        self.client = client or httpx2.Client(timeout=timeout_s)
        # OpenAI-style knob for reasoning models ("none" | "low" | "medium" | "high").
        # Ollama honors it on /v1; servers that don't know it ignore it.
        self.reasoning_effort = reasoning_effort
        self.api_key_env = api_key_env

    def _headers(self) -> dict[str, str]:
        if not self.api_key_env:
            return {}
        key = os.environ.get(self.api_key_env, "")
        if not key:
            raise MissingAPIKey(f"{self.api_key_env} is not set (needed for {self.base_url})")
        return {"Authorization": f"Bearer {key}"}

    def complete(self, *, model, system, messages, max_tokens, cache):
        body = {
            "model": model,
            "messages": [{"role": "system", "content": system}, *messages],
            "max_tokens": max_tokens,
            "stream": False,
        }
        if self.reasoning_effort:
            body["reasoning_effort"] = self.reasoning_effort
        resp = self.client.post(f"{self.base_url}/chat/completions", json=body, headers=self._headers())
        resp.raise_for_status()
        data = resp.json()
        choice = data["choices"][0]
        text, reasoning = message_content(choice["message"])
        usage = data.get("usage") or {}
        finish = choice.get("finish_reason")
        if not text.strip() and finish == "length":
            raise TruncatedOutput(
                f"{model} used all {max_tokens} output tokens without answering "
                f"(reasoning: {len(reasoning)} chars). Raise max_tokens or lower reasoning_effort."
            )
        cached = (usage.get("prompt_tokens_details") or {}).get("cached_tokens", 0) or 0
        return Completion(
            text=text,
            model=model,
            usage=Usage(
                input_tokens=max(usage.get("prompt_tokens", 0) - cached, 0),
                output_tokens=usage.get("completion_tokens", 0),
                cache_read_tokens=cached,
            ),
            stop_reason=finish,
            reasoning=reasoning,
        )

    def list_models(self) -> list[str]:
        resp = self.client.get(f"{self.base_url}/models", headers=self._headers())
        resp.raise_for_status()
        return [m["id"] for m in resp.json().get("data", [])]


# llm-server is just the keyless case.
LocalProvider = OpenAICompatProvider
