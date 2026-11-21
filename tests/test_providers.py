"""Exercise the real LocalProvider against a mock HTTP transport (no network)."""

import json

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
