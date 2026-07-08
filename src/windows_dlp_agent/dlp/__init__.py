"""DLP detection engine (spec §4).

Public surface:
    Finding, Decision, Action  -- data model
    DlpEngine                  -- scan / evaluate / redact
    default_engine()           -- engine with the built-in detector set
"""

from __future__ import annotations

from .engine import Action, Decision, DlpEngine, Finding, default_engine

__all__ = ["Action", "Decision", "DlpEngine", "Finding", "default_engine"]
