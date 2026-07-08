"""Tests for override store, fingerprinting, audit, control (spec §5)."""

from __future__ import annotations

import json

from windows_dlp_agent.audit import AuditLog
from windows_dlp_agent.dlp import default_engine
from windows_dlp_agent.override import OverrideStore, fingerprint


class _Clock:
    def __init__(self):
        self.t = 0.0

    def __call__(self) -> float:
        return self.t


def test_fingerprint_normalizes_whitespace_and_hides_prompt():
    a = fingerprint("chatgpt.com", "hello   world")
    b = fingerprint("chatgpt.com", "hello world")
    assert a == b
    assert "hello" not in a  # only a hash


def test_fingerprint_differs_by_host_and_content():
    assert fingerprint("a.com", "x") != fingerprint("b.com", "x")
    assert fingerprint("a.com", "x") != fingerprint("a.com", "y")


def test_override_consume_is_one_shot():
    store = OverrideStore(ttl_seconds=100, clock=_Clock())
    fp = fingerprint("chatgpt.com", "secret")
    store.grant(fp)
    assert store.consume(fp) is True
    assert store.consume(fp) is False  # consumed


def test_override_expires():
    clock = _Clock()
    store = OverrideStore(ttl_seconds=100, clock=clock)
    fp = fingerprint("chatgpt.com", "secret")
    store.grant(fp)
    clock.t = 101
    assert store.is_granted(fp) is False
    assert store.consume(fp) is False


def test_override_purges_expired():
    clock = _Clock()
    store = OverrideStore(ttl_seconds=10, clock=clock)
    store.grant("a")
    store.grant("b")
    clock.t = 11
    assert store.purge_expired() == 2


def test_audit_writes_masked_jsonl(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    dec = default_engine().evaluate("card 4111 1111 1111 1111")
    log.record_decision(
        host="chatgpt.com", service="ChatGPT", path="/c", decision=dec, outcome="block"
    )
    lines = (tmp_path / "audit.jsonl").read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    event = json.loads(lines[0])
    assert event["type"] == "decision"
    assert event["outcome"] == "block"
    assert event["action"] == "block"
    # raw card number must not appear anywhere in the audit record
    assert "4111 1111 1111 1111" not in lines[0]
    assert "financial" in event["categories"]


def test_audit_override_record(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    log.record_override(host="claude.ai", service="Claude", fingerprint="abc123")
    event = json.loads((tmp_path / "audit.jsonl").read_text(encoding="utf-8").strip())
    assert event["type"] == "override"
    assert event["fingerprint"] == "abc123"
