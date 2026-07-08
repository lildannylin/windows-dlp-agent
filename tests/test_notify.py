"""Tests for the notification module (spec §5)."""

from __future__ import annotations

from windows_dlp_agent.notify import RecordingNotifier, build_message, get_notifier


def test_build_message_block_mentions_type_and_service():
    title, body = build_message(["financial"], "ChatGPT", "block")
    assert "阻擋" in title
    assert "financial" in body
    assert "ChatGPT" in body


def test_build_message_defaults_service():
    _title, body = build_message([], None, "warn")
    assert "AI 服務" in body


def test_recording_notifier_records():
    n = RecordingNotifier()
    n.notify("t", "b")
    assert n.messages == [("t", "b")]


def test_get_notifier_returns_usable_notifier():
    n = get_notifier()
    # Must not raise; both real and recording notifiers satisfy .notify()
    n.notify("hello", "world")
