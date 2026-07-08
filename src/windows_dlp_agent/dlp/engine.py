"""DLP engine: layered detection + precision-tiered actions (spec §4).

Layers (high precision -> low, §4.2):
    1. structured pattern + checksum   -> block   (near-zero FP)
    2. structured pattern (prefix)     -> block
    3. high Shannon entropy tokens     -> warn
    4. keyword / dictionary            -> warn

Actions follow §4.3: structured+checksum hard-block; heuristic -> warn-with-override.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Callable, Iterable

from .checksums import (
    luhn_valid,
    shannon_entropy,
    taiwan_id_valid,
    taiwan_ubn_valid,
)

__all__ = ["Action", "Finding", "Decision", "DlpEngine", "default_engine"]


class Action(IntEnum):
    """Ordered by severity so max() picks the strongest action for a request."""

    ALLOW = 0
    REDACT = 1
    WARN = 2  # warn-with-override
    BLOCK = 3

    @property
    def label(self) -> str:
        return self.name.lower()


@dataclass(frozen=True)
class Finding:
    category: str  # §4.1 class, e.g. "credential", "pii", "financial"
    detector: str  # specific rule, e.g. "openai_api_key"
    action: Action
    start: int
    end: int
    matched: str
    confidence: str = "high"

    def preview(self) -> str:
        """Short, masked view safe to put in a toast/log (never the full secret)."""
        m = self.matched
        if len(m) <= 8:
            return m[0] + "***" if m else "***"
        return f"{m[:4]}…{m[-2:]}"


@dataclass
class Decision:
    action: Action
    findings: list[Finding] = field(default_factory=list)

    @property
    def blocked(self) -> bool:
        return self.action >= Action.WARN

    @property
    def categories(self) -> list[str]:
        seen: dict[str, None] = {}
        for f in self.findings:
            seen.setdefault(f.category, None)
        return list(seen)


# A detector yields Findings for a piece of text.
Detector = Callable[[str], Iterable[Finding]]


def _regex_detector(
    name: str,
    category: str,
    pattern: str,
    action: Action,
    *,
    validator: Callable[[str], bool] | None = None,
    flags: int = 0,
    confidence: str = "high",
) -> Detector:
    rx = re.compile(pattern, flags)

    def detect(text: str) -> Iterable[Finding]:
        for m in rx.finditer(text):
            value = m.group(m.lastindex or 0)
            if validator is not None and not validator(value):
                continue
            start, end = m.span(m.lastindex or 0)
            yield Finding(category, name, action, start, end, value, confidence)

    return detect


# --- Structured credential / secret detectors (§4.1 credentials) -------------

_CREDENTIAL_DETECTORS: list[Detector] = [
    _regex_detector(
        "openai_api_key", "credential",
        r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b", Action.BLOCK,
    ),
    _regex_detector(
        "anthropic_api_key", "credential",
        r"\bsk-ant-[A-Za-z0-9_-]{20,}\b", Action.BLOCK,
    ),
    _regex_detector(
        "aws_access_key", "credential",
        r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b", Action.BLOCK,
    ),
    _regex_detector(
        "gcp_api_key", "credential",
        r"\bAIza[0-9A-Za-z_-]{35}\b", Action.BLOCK,
    ),
    _regex_detector(
        "github_token", "credential",
        r"\bgh[pousr]_[A-Za-z0-9]{36,}\b", Action.BLOCK,
    ),
    _regex_detector(
        "slack_token", "credential",
        r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b", Action.BLOCK,
    ),
    _regex_detector(
        "jwt", "credential",
        r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b",
        Action.BLOCK,
    ),
    _regex_detector(
        "private_key_pem", "credential",
        r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----",
        Action.BLOCK,
    ),
    _regex_detector(
        "db_connection_string", "credential",
        r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[^\s\"']+:[^\s\"'@]+@[^\s\"']+",
        Action.BLOCK,
    ),
]

# --- PII (localized, §4.1) ---------------------------------------------------

_PII_DETECTORS: list[Detector] = [
    _regex_detector(
        "taiwan_id", "pii",
        r"\b[A-Z][12][0-9]{8}\b", Action.BLOCK, validator=taiwan_id_valid,
    ),
    _regex_detector(
        "taiwan_ubn", "pii",
        r"\b[0-9]{8}\b", Action.BLOCK, validator=taiwan_ubn_valid,
    ),
    _regex_detector(
        "email", "pii",
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
        Action.WARN, confidence="medium",
    ),
    _regex_detector(
        "taiwan_phone", "pii",
        r"\b09[0-9]{2}[- ]?[0-9]{3}[- ]?[0-9]{3}\b",
        Action.WARN, confidence="medium",
    ),
]

# --- Financial (§4.1) --------------------------------------------------------

_FINANCIAL_DETECTORS: list[Detector] = [
    _regex_detector(
        "credit_card", "financial",
        r"\b(?:[0-9][ -]?){12,18}[0-9]\b", Action.BLOCK, validator=luhn_valid,
    ),
    _regex_detector(
        "iban", "financial",
        r"\b[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}\b",
        Action.WARN, confidence="medium",
    ),
]

# --- Company confidential keywords (§4.1) ------------------------------------

DEFAULT_KEYWORDS = [
    "機密", "極機密", "營業秘密", "內部限閱",
    "confidential", "internal only", "proprietary", "trade secret",
]


def _keyword_detector(keywords: list[str]) -> Detector:
    if not keywords:
        return lambda _text: ()
    rx = re.compile("|".join(re.escape(k) for k in keywords), re.IGNORECASE)

    def detect(text: str) -> Iterable[Finding]:
        for m in rx.finditer(text):
            yield Finding(
                "confidential", "keyword", Action.WARN,
                m.start(), m.end(), m.group(0), "medium",
            )

    return detect


# --- High-entropy token detector (§4.2) --------------------------------------

_TOKEN_RE = re.compile(r"[A-Za-z0-9+/=_-]{20,}")


def _entropy_detector(threshold: float = 4.0) -> Detector:
    def detect(text: str) -> Iterable[Finding]:
        for m in _TOKEN_RE.finditer(text):
            tok = m.group(0)
            if shannon_entropy(tok) >= threshold:
                yield Finding(
                    "credential", "high_entropy", Action.WARN,
                    m.start(), m.end(), tok, "low",
                )

    return detect


class DlpEngine:
    """Runs a set of detectors over text and produces a Decision (§4.3)."""

    def __init__(self, detectors: list[Detector]):
        self._detectors = detectors

    def scan(self, text: str) -> list[Finding]:
        if not text:
            return []
        findings: list[Finding] = []
        for det in self._detectors:
            findings.extend(det(text))
        findings.sort(key=lambda f: (f.start, -int(f.action)))
        return _dedupe_overlaps(findings)

    def evaluate(self, text: str) -> Decision:
        findings = self.scan(text)
        action = max((f.action for f in findings), default=Action.ALLOW)
        return Decision(action=action, findings=findings)

    def redact(self, text: str, findings: list[Finding] | None = None) -> str:
        """Replace matched spans with [REDACTED] (§5 redact action)."""
        spans = findings if findings is not None else self.scan(text)
        out = text
        for f in sorted(spans, key=lambda f: f.start, reverse=True):
            out = out[: f.start] + "[REDACTED]" + out[f.end :]
        return out


def _dedupe_overlaps(findings: list[Finding]) -> list[Finding]:
    """Drop a finding fully covered by an earlier, at-least-as-severe one.

    Keeps e.g. an entropy match from firing on top of a recognised API key.
    """
    kept: list[Finding] = []
    for f in findings:
        covered = any(
            k.start <= f.start and f.end <= k.end and k.action >= f.action
            for k in kept
        )
        if not covered:
            kept.append(f)
    return kept


def default_engine(*, keywords: list[str] | None = None) -> DlpEngine:
    """Engine with the built-in detector set (§4.1 coverage)."""
    detectors: list[Detector] = []
    detectors += _CREDENTIAL_DETECTORS
    detectors += _PII_DETECTORS
    detectors += _FINANCIAL_DETECTORS
    detectors.append(_keyword_detector(DEFAULT_KEYWORDS if keywords is None else keywords))
    detectors.append(_entropy_detector())
    return DlpEngine(detectors)
