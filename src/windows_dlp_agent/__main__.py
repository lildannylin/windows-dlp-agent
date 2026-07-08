"""Command-line entry point for the Windows DLP agent (spec §3/§9)."""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from pathlib import Path

from . import __version__
from .ca import CertificateAuthority
from .config import Config
from .proxy import run as run_proxy


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="windows-dlp-agent", description=__doc__)
    p.add_argument("--version", action="version", version=f"windows-dlp-agent {__version__}")
    p.add_argument("--host", default="127.0.0.1", help="listen address (default 127.0.0.1)")
    p.add_argument("--port", type=int, default=8080, help="listen port (default 8080)")
    p.add_argument("--ca-dir", type=Path, default=None, help="CA directory (default ~/.windows-dlp-agent/ca)")
    p.add_argument("-v", "--verbose", action="count", default=0, help="-v info, -vv debug")

    sub = p.add_subparsers(dest="command")
    export = sub.add_parser("export-ca", help="write the root CA cert to a path and exit")
    export.add_argument("output", type=Path, help="destination .crt file")
    return p


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    args = _build_parser().parse_args(argv)

    logging.basicConfig(
        level=logging.WARNING - 10 * min(args.verbose, 2),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    config = Config(host=args.host, port=args.port)
    if args.ca_dir is not None:
        config.ca_dir = Path(args.ca_dir)

    if args.command == "export-ca":
        ca = CertificateAuthority.load_or_generate(config.ca_dir)
        args.output.write_bytes(ca.cert_pem())
        print(f"Root CA written to {args.output}")
        print("Install it into the endpoint's Trusted Root store (see spec section 6),")
        print(f"then set the browser proxy to {config.host}:{config.port} (fixed_servers).")
        return 0

    print(f"windows-dlp-agent {__version__} — MITM DLP proxy on {config.host}:{config.port}")
    print(f"CA dir: {config.ca_dir}")
    try:
        asyncio.run(run_proxy(config))
    except KeyboardInterrupt:
        print("\nshutting down")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
