"""Unit tests for proxy helpers (no network)."""

from __future__ import annotations

from windows_dlp_agent.proxy import _upstream_url


def test_origin_form_composes_https():
    assert _upstream_url("chatgpt.com", 443, "/backend-api/conversation") == \
        "https://chatgpt.com/backend-api/conversation"


def test_origin_form_nondefault_port_keeps_port():
    assert _upstream_url("127.0.0.1", 8443, "/x") == "https://127.0.0.1:8443/x"


def test_absolute_form_used_verbatim_no_scheme_doubling():
    # Regression: plain-HTTP absolute-URI target must not become
    # "https://host" + "http://host/..." (found via live Chrome traffic).
    target = "http://clients2.google.com/time/1/current?cup2key=x"
    assert _upstream_url("clients2.google.com", 443, target) == target


def test_absolute_https_form_used_verbatim():
    target = "https://example.com/a?b=c"
    assert _upstream_url("example.com", 443, target) == target
