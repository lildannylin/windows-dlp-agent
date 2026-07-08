"""Tests for the DLP engine (spec §4)."""

from __future__ import annotations

import pytest

from windows_dlp_agent.dlp import Action, default_engine
from windows_dlp_agent.dlp.checksums import (
    luhn_valid,
    shannon_entropy,
    taiwan_id_valid,
    taiwan_ubn_valid,
)


# --- checksums ---------------------------------------------------------------


def test_luhn_valid_card():
    assert luhn_valid("4111 1111 1111 1111")
    assert luhn_valid("4111-1111-1111-1111")


def test_luhn_rejects_bad_card_and_short():
    assert not luhn_valid("4111 1111 1111 1112")
    assert not luhn_valid("1234")


@pytest.mark.parametrize("valid_id", ["A123456789", "F131104093"])
def test_taiwan_id_valid(valid_id):
    assert taiwan_id_valid(valid_id)


def test_taiwan_id_rejects_bad_checksum_and_shape():
    assert not taiwan_id_valid("A123456788")
    assert not taiwan_id_valid("A023456789")  # gender digit must be 1/2
    assert not taiwan_id_valid("1234567890")


def test_taiwan_ubn():
    assert taiwan_ubn_valid("04595257")  #台積電-style valid UBN
    assert not taiwan_ubn_valid("12345678")
    assert not taiwan_ubn_valid("1234567")


def test_entropy_orders_random_above_repetitive():
    assert shannon_entropy("aaaaaaaa") < shannon_entropy("aB3xZ9qL")


# --- engine: blocks (structured + checksum, §4.3) ----------------------------


def test_blocks_fake_credit_card():
    eng = default_engine()
    dec = eng.evaluate("here is my card 4111 1111 1111 1111 ok?")
    assert dec.action is Action.BLOCK
    assert any(f.detector == "credit_card" for f in dec.findings)


def test_blocks_openai_key():
    eng = default_engine()
    dec = eng.evaluate("key=sk-abcdefghijklmnopqrstuvwxyz0123")
    assert dec.action is Action.BLOCK
    assert any(f.detector == "openai_api_key" for f in dec.findings)


def test_blocks_aws_key_and_pem():
    eng = default_engine()
    assert eng.evaluate("AKIAIOSFODNN7EXAMPLE").action is Action.BLOCK
    assert eng.evaluate("-----BEGIN RSA PRIVATE KEY-----").action is Action.BLOCK


def test_blocks_taiwan_id():
    eng = default_engine()
    dec = eng.evaluate("身分證 A123456789 請保密")
    assert dec.action is Action.BLOCK
    assert any(f.detector == "taiwan_id" for f in dec.findings)


# --- engine: warn tier (§4.3) ------------------------------------------------


def test_email_only_is_warn_not_block():
    eng = default_engine()
    dec = eng.evaluate("contact me at alice@example.com")
    assert dec.action is Action.WARN


def test_keyword_confidential_is_warn():
    eng = default_engine()
    dec = eng.evaluate("這份文件屬於營業秘密，請勿外流")
    assert dec.action is Action.WARN
    assert any(f.category == "confidential" for f in dec.findings)


# --- engine: clean text allows ----------------------------------------------


def test_clean_text_allows():
    eng = default_engine()
    dec = eng.evaluate("What is the capital of France?")
    assert dec.action is Action.ALLOW
    assert dec.findings == []


# --- redaction (§5) ----------------------------------------------------------


def test_redact_replaces_secret():
    eng = default_engine()
    text = "card 4111 1111 1111 1111 done"
    out = eng.redact(text)
    assert "4111" not in out
    assert "[REDACTED]" in out
    assert out.startswith("card ") and out.endswith(" done")


def test_finding_preview_masks_secret():
    eng = default_engine()
    dec = eng.evaluate("key=sk-abcdefghijklmnopqrstuvwxyz0123")
    f = next(f for f in dec.findings if f.detector == "openai_api_key")
    assert "…" in f.preview()
    assert f.matched not in f.preview()
