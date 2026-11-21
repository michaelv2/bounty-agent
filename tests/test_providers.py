"""Exercise the real LocalProvider against a mock HTTP transport (no network)."""

import json

import pytest

import httpx2

from bounty_agent.router import LocalProvider


def make_provider(handler):
    client = httpx2.Client(transport=httpx2.MockTransport(handler))
    return LocalProvider("http://llm.test/v1/", client=client)


def test_default_client_constructs():
    # Catches a missing or broken httpx2 import, which mocked tests would hide.
    assert isinstance(LocalProvider("http://llm.test/v1").client, httpx2.Client)


def test_chat_completion_request_and_usage():
    seen = {}

    def handler(request):
        seen["url"] = str(request.url)
        seen["body"] = json.loads(request.content)
        return httpx2.Response(200, json={
            "choices": [{"message": {"content": "hotspot: Vault.withdraw"}}],
            "usage": {"prompt_tokens": 120, "completion_tokens": 8},
        })

    out = make_provider(handler).complete(
        model="qwen-test", system="sys", messages=[{"role": "user", "content": "hi"}], max_tokens=50, cache=False
    )
    assert seen["url"] == "http://llm.test/v1/chat/completions"
    assert seen["body"]["messages"][0] == {"role": "system", "content": "sys"}
    assert seen["body"]["stream"] is False
    assert out.text == "hotspot: Vault.withdraw"
    assert (out.usage.input_tokens, out.usage.output_tokens) == (120, 8)


def test_list_models():
    def handler(request):
        assert request.url.path == "/v1/models"
        return httpx2.Response(200, json={"data": [{"id": "qwen3.8:27b"}, {"id": "other"}]})

    assert make_provider(handler).list_models() == ["qwen3.8:27b", "other"]


def test_reasoning_effort_sent_and_reasoning_kept_apart():
    seen = {}

    def handler(request):
        seen["body"] = json.loads(request.content)
        return httpx2.Response(200, json={
            "choices": [{"message": {"content": "[]", "reasoning": "thinking..."}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5},
        })

    p = LocalProvider("http://llm.test/v1", client=httpx2.Client(transport=httpx2.MockTransport(handler)),
                      reasoning_effort="low")
    out = p.complete(model="m", system="s", messages=[], max_tokens=50, cache=False)
    assert seen["body"]["reasoning_effort"] == "low"
    assert out.text == "[]" and out.reasoning == "thinking..." and out.stop_reason == "stop"


def test_budget_spent_on_thinking_raises_instead_of_returning_empty():
    """Seen on llm-server 2026-11-21: qwen3.8 used all 800 tokens reasoning and returned ''."""
    import pytest

    from bounty_agent.router import TruncatedOutput

    def handler(request):
        return httpx2.Response(200, json={
            "choices": [{"message": {"content": "", "reasoning": "x" * 3000}, "finish_reason": "length"}],
            "usage": {"prompt_tokens": 1334, "completion_tokens": 800},
        })

    with pytest.raises(TruncatedOutput, match="without answering"):
        make_provider(handler).complete(model="m", system="s", messages=[], max_tokens=800, cache=False)


# ---- Mistral-hosted provider (OpenAICompatProvider) ----

def test_message_content_handles_mistral_reasoning_list():
    from bounty_agent.router.providers import message_content

    msg = {"content": [
        {"type": "thinking", "thinking": [{"type": "text", "text": "let me think"}]},
        {"type": "text", "text": "the answer"},
    ]}
    text, reasoning = message_content(msg)
    assert text == "the answer" and reasoning == "let me think"
    assert message_content({"content": "plain"}) == ("plain", "")
    assert message_content({"content": None, "reasoning": "r"}) == ("", "r")


def test_remote_provider_sends_key_and_splits_cached_tokens(monkeypatch):
    from bounty_agent.router.providers import MissingAPIKey, OpenAICompatProvider

    seen = {}

    def handler(request):
        seen["auth"] = request.headers.get("authorization")
        return httpx2.Response(200, json={
            "choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 1000, "completion_tokens": 50,
                      "prompt_tokens_details": {"cached_tokens": 800}},
        })

    monkeypatch.setenv("TEST_KEY", "secret-xyz")
    p = OpenAICompatProvider("https://api.test/v1", client=httpx2.Client(transport=httpx2.MockTransport(handler)),
                             api_key_env="TEST_KEY")
    out = p.complete(model="deepseek", system="s", messages=[{"role": "user", "content": "hi"}],
                     max_tokens=50, cache=False)
    assert seen["auth"] == "Bearer secret-xyz"
    assert out.usage.input_tokens == 200 and out.usage.cache_read_tokens == 800  # cached split out

    monkeypatch.delenv("TEST_KEY")
    with pytest.raises(MissingAPIKey, match="TEST_KEY"):
        p.complete(model="m", system="s", messages=[], max_tokens=1, cache=False)
