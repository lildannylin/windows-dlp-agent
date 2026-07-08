"""Runtime configuration / policy (spec §5/§6)."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

__all__ = ["Config"]


def _default_ca_dir() -> Path:
    return Path.home() / ".windows-dlp-agent" / "ca"


@dataclass
class Config:
    host: str = "127.0.0.1"
    port: int = 8080
    ca_dir: Path = field(default_factory=_default_ca_dir)

    # Verify upstream (real server) certificates when forwarding. True in
    # production; tests point at a self-signed upstream and set this False.
    upstream_verify: bool = True

    # Custom confidential keywords appended to the defaults (§4.1). None => defaults.
    keywords: list[str] | None = None

    # Policy: which engine Action maps to actually dropping the request.
    # WARN and BLOCK both stop the request (warn = block + override prompt, §4.3/§5).
    def __post_init__(self) -> None:
        self.ca_dir = Path(self.ca_dir)
