"""Tests for prompt extraction (spec §4.4)."""

from __future__ import annotations

import json

from windows_dlp_agent.extract import (
    extract_prompt,
    host_from_url,
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


def test_extract_claude_messages():
    body = json.dumps(
        {"messages": [{"role": "user", "content": "my key sk-abc"}]}
    ).encode()
    text = extract_prompt("claude.ai", "/api/organizations/x/chat_conversations/y/completion", body)
    assert "sk-abc" in text


def test_generic_fallback_json():
    body = json.dumps({"q": "find me AKIAIOSFODNN7EXAMPLE please"}).encode()
    text = extract_prompt("some-shadow-ai.example", "/v1/ask", body)
    assert "AKIAIOSFODNN7EXAMPLE" in text


def test_generic_fallback_plain_text():
    text = extract_prompt("x.example", "/p", b"raw prompt body")
    assert text == "raw prompt body"


def test_returns_none_on_empty():
    assert extract_prompt("x.example", "/p", b"") is None


def test_host_from_url():
    assert host_from_url("https://chatgpt.com:443/backend-api") == "chatgpt.com"
    assert host_from_url("chatgpt.com:443") == "chatgpt.com"
    assert host_from_url("user@claude.ai:443") == "claude.ai"
