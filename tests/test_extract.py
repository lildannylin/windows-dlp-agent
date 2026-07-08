"""Tests for prompt extraction (spec §4.4)."""

from __future__ import annotations

import json
from urllib.parse import urlencode

from windows_dlp_agent.extract import (
    extract_prompt,
    host_from_url,
    register_extractor,
    register_service,
    service_for_host,
)


def test_service_for_host():
    assert service_for_host("chatgpt.com") == "ChatGPT"
    assert service_for_host("gemini.google.com") == "Gemini"
    assert service_for_host("claude.ai") == "Claude"
    assert service_for_host("example.com") is None


def test_extract_chatgpt_parts():
    body = json.dumps(
        {
            "messages": [
                {"content": {"parts": ["hello ", "secret 4111 1111 1111 1111"]}},
            ]
        }
    ).encode()
    text = extract_prompt("chatgpt.com", "/backend-api/f/conversation", body)
    assert "4111 1111 1111 1111" in text


def test_extract_chatgpt_current_web_payload():
    """Exact shape verified against live chatgpt.com traffic (author/content_type/action)."""
    body = json.dumps(
        {
            "action": "next",
            "messages": [
                {
                    "author": {"role": "user"},
                    "content": {
                        "content_type": "text",
                        "parts": ["leak sk-abcdefghijklmnopqrstuvwxyz0123"],
                    },
                    "id": "aaaa-bbbb",
                    "role": "user",
                }
            ],
            "model": "gpt-4o",
            "parent_message_id": "cccc-dddd",
        }
    ).encode()
    text = extract_prompt("chatgpt.com", "/backend-api/f/conversation", body)
    assert "sk-abcdefghijklmnopqrstuvwxyz0123" in text


def test_extract_chatgpt_multimodal_dict_parts():
    body = json.dumps(
        {
            "messages": [
                {
                    "author": {"role": "user"},
                    "content": {
                        "content_type": "multimodal_text",
                        "parts": [
                            {"content_type": "image_asset_pointer", "asset_pointer": "file-x"},
                            {"content_type": "audio_transcription", "text": "my card 4111 1111 1111 1111"},
                            "and some trailing text",
                        ],
                    },
                }
            ]
        }
    ).encode()
    text = extract_prompt("chatgpt.com", "/backend-api/conversation", body)
    assert "4111 1111 1111 1111" in text
    assert "and some trailing text" in text


def test_extract_claude_messages():
    body = json.dumps(
        {"messages": [{"role": "user", "content": "my key sk-abc"}]}
    ).encode()
    text = extract_prompt("claude.ai", "/api/organizations/x/chat_conversations/y/completion", body)
    assert "sk-abc" in text


def test_extract_gemini_batchexecute():
    inner = json.dumps([["please summarize AKIAIOSFODNN7EXAMPLE"], None, None])
    freq = json.dumps([[["hNvQHb", inner, None, "generic"]]])
    body = urlencode({"f.req": freq, "at": "token"}).encode()
    text = extract_prompt("gemini.google.com", "/_/BardChatUi/data/batchexecute", body)
    assert "AKIAIOSFODNN7EXAMPLE" in text


def test_register_service_and_extractor():
    def _mine(req):
        return "custom prompt from extractor"

    register_service("myai.internal", "MyAI", extractor=_mine)
    assert service_for_host("chat.myai.internal") == "MyAI"
    assert extract_prompt("myai.internal", "/x", b"{}") == "custom prompt from extractor"


def test_register_extractor_attaches_to_host():
    def _other(req):
        return "from register_extractor"

    register_extractor("otherai.internal", _other)
    assert extract_prompt("otherai.internal", "/x", b"{}") == "from register_extractor"
    # a different, unregistered host is still not scanned
    assert extract_prompt("nope.example", "/x", b"{}") is None


def test_known_service_nonprompt_endpoint_not_scanned():
    """Regression (found via live Chrome): a known AI host's infra endpoints
    (Cloudflare challenge, telemetry) must NOT be swept, or their random tokens
    false-positive. Only the real prompt endpoint yields a prompt."""
    challenge_body = b'{"token":"QJCcjZcEMW4qtiAVCN+LUYu3mOs5AiYbdelBFJPFLPb1I-KiKW"}'
    assert extract_prompt(
        "chatgpt.com",
        "/cdn-cgi/challenge-platform/h/b/fo/2388486502/xyz",
        challenge_body,
    ) is None


def test_unrecognized_host_never_scanned():
    """Regression (found via live Chrome): arbitrary hosts — Cloudflare
    challenges, Google telemetry, any normal site — must NOT be scanned, so DLP
    can't block ordinary web traffic. Even a body containing a real secret is
    passed through untouched when the host isn't a recognized AI destination."""
    body = json.dumps({"q": "find AKIAIOSFODNN7EXAMPLE"}).encode()
    assert extract_prompt("challenges.cloudflare.com", "/cdn-cgi/x", body) is None
    assert extract_prompt("update.googleapis.com", "/service/update2/json", body) is None
    assert extract_prompt("some-random-site.example", "/v1/ask", body) is None


def test_shadow_ai_host_scanned_after_register_with_generic():
    # A shadow-AI host is opted in explicitly; without a bespoke extractor it
    # gets the generic JSON string sweep.
    register_service("shadowai.example", "ShadowAI")
    body = json.dumps({"q": "find me AKIAIOSFODNN7EXAMPLE please"}).encode()
    text = extract_prompt("chat.shadowai.example", "/v1/ask", body)
    assert "AKIAIOSFODNN7EXAMPLE" in text


def test_returns_none_on_empty_even_for_known_host():
    assert extract_prompt("chatgpt.com", "/backend-api/conversation", b"") is None


def test_host_from_url():
    assert host_from_url("https://chatgpt.com:443/backend-api") == "chatgpt.com"
    assert host_from_url("chatgpt.com:443") == "chatgpt.com"
    assert host_from_url("user@claude.ai:443") == "claude.ai"
