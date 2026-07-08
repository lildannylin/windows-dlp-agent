"""Append-only audit log of DLP decisions and overrides (spec §5).

Every hit, override, and block is recorded as one JSON line. Raw sensitive
values are NEVER written — only masked previews and detector names — so the
audit trail itself is not a data-leak surface.
"""

from __future__ import annotations

import datetime as _dt
import json
import threading
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .dlp import Decision

__all__ = ["AuditLog", "NullAuditLog"]


def _now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat()


class AuditLog:
    """Thread-safe JSONL audit sink."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def _write(self, event: dict) -> None:
        event.setdefault("ts", _now_iso())
        line = json.dumps(event, ensure_ascii=False)
        with self._lock:
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")

    def record_decision(
        self, *, host: str, service: str | None, path: str, decision: "Decision", outcome: str
    ) -> None:
        """Record a DLP decision. `outcome` in {block, warn, redact, allow-override}."""
        self._write(
            {
                "type": "decision",
                "host": host,
                "service": service,
                "path": path,
                "action": decision.action.label,
                "outcome": outcome,
                "categories": decision.categories,
                "findings": [
                    {"detector": f.detector, "category": f.category,
                     "preview": f.preview(), "confidence": f.confidence}
                    for f in decision.findings
                ],
            }
        )

    def record_override(self, *, host: str, service: str | None, fingerprint: str) -> None:
        self._write(
            {
                "type": "override",
                "host": host,
                "service": service,
                "fingerprint": fingerprint,
            }
        )


class NullAuditLog:
    """Audit sink that discards everything (default when no path configured)."""

    def record_decision(self, **_kw) -> None:  # noqa: D401
        pass

    def record_override(self, **_kw) -> None:
        pass
