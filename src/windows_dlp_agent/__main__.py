"""Command-line entry point for the Windows DLP agent."""

from __future__ import annotations

import sys

from . import __version__


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    print(f"windows-dlp-agent {__version__}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
