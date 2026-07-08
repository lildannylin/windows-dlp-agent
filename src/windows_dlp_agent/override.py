"""warn-with-override support (spec §4.3/§5).

A WARN-tier hit is blocked first, then the user may explicitly approve sending
this exact content. Approval is keyed by a content fingerprint (host + prompt),
is one-shot, and expires after a TTL so a stale grant can't silently reopen the
door. BLOCK-tier hits are never overridable.
"""

from __future__ import annotations

import hashlib
import threading
import time
from typing import Callable

__all__ = ["fingerprint", "OverrideStore"]


def fingerprint(host: str, prompt: str) -> str:
    """Stable id for (host, prompt); whitespace-normalised so trivial edits match.

    Only a hash is stored/transmitted — never the prompt text itself.
    """
    norm = " ".join(prompt.split())
    return hashlib.sha256(f"{host}\n{norm}".encode("utf-8")).hexdigest()


class OverrideStore:
    """One-shot, TTL-bounded approvals keyed by fingerprint."""

    def __init__(self, ttl_seconds: float = 300.0, *, clock: Callable[[], float] = time.monotonic):
        self._ttl = ttl_seconds
        self._clock = clock
        self._grants: dict[str, float] = {}
        self._lock = threading.Lock()

    def grant(self, fp: str) -> None:
        with self._lock:
            self._grants[fp] = self._clock() + self._ttl

    def consume(self, fp: str) -> bool:
        """True exactly once if a live grant exists; removes it (one-shot)."""
        now = self._clock()
        with self._lock:
            expiry = self._grants.pop(fp, None)
            return expiry is not None and expiry >= now

    def is_granted(self, fp: str) -> bool:
        """Peek without consuming (does purge if expired)."""
        now = self._clock()
        with self._lock:
            expiry = self._grants.get(fp)
            if expiry is None:
                return False
            if expiry < now:
                del self._grants[fp]
                return False
            return True

    def purge_expired(self) -> int:
        now = self._clock()
        with self._lock:
            stale = [k for k, exp in self._grants.items() if exp < now]
            for k in stale:
                del self._grants[k]
            return len(stale)
