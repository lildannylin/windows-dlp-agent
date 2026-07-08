"""Command-line entry point for the Windows DLP agent (spec sections 3/6/9)."""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
import urllib.request
from pathlib import Path

from . import __version__
from .ca import CertificateAuthority
from .config import Config
from .deploy import write_bundle
from .proxy import run as run_proxy


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="windows-dlp-agent", description=__doc__)
    p.add_argument("--version", action="version", version=f"windows-dlp-agent {__version__}")
    p.add_argument("--host", default="127.0.0.1", help="listen address (default 127.0.0.1)")
    p.add_argument("--port", type=int, default=8080, help="listen port (default 8080)")
    p.add_argument("--ca-dir", type=Path, default=None, help="CA directory (default ~/.windows-dlp-agent/ca)")
    p.add_argument("--audit-log", type=Path, default=None, help="JSONL audit log path (spec section 5)")
    p.add_argument("--control-port", type=int, default=None, help="loopback override control port (spec section 5)")
    p.add_argument("--websocket", choices=["relay", "block"], default="relay",
                   help="WebSocket policy: relay (fail-open, default) or block (fail-closed)")
    p.add_argument("-v", "--verbose", action="count", default=0, help="-v info, -vv debug")

    sub = p.add_subparsers(dest="command")

    export = sub.add_parser("export-ca", help="write the root CA cert to a path and exit")
    export.add_argument("output", type=Path, help="destination .crt file")

    bundle = sub.add_parser("deploy-bundle", help="write reg policy + CA + install.ps1 (spec section 6)")
    bundle.add_argument("output_dir", type=Path, help="destination directory")

    ov = sub.add_parser("override", help="grant a one-shot override via the control endpoint")
    ov.add_argument("fingerprint", help="content fingerprint from the audit log / toast")
    ov.add_argument("--control-port", type=int, required=True, help="running proxy's control port")

    return p


def _run_export_ca(config: Config, output: Path) -> int:
    ca = CertificateAuthority.load_or_generate(config.ca_dir)
    output.write_bytes(ca.cert_pem())
    print(f"Root CA written to {output}")
    print("Install it into the endpoint's Trusted Root store (see spec section 6),")
    print(f"then set the browser proxy to {config.host}:{config.port} (fixed_servers).")
    return 0


def _run_deploy_bundle(config: Config, output_dir: Path) -> int:
    ca = CertificateAuthority.load_or_generate(config.ca_dir)
    paths = write_bundle(output_dir, config, ca.cert_pem())
    print("Deploy bundle written:")
    for name, path in paths.items():
        print(f"  {name}: {path}")
    print("Push via GPO / Intune / MDM, or run install.ps1 as Administrator (spec section 6).")
    return 0


def _run_override(fingerprint: str, control_port: int) -> int:
    body = json.dumps({"fingerprint": fingerprint}).encode()
    req = urllib.request.Request(
        f"http://127.0.0.1:{control_port}/override",
        data=body,
        headers={"content-type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            print(f"override: {resp.status} {resp.read().decode()}")
        return 0
    except OSError as exc:
        print(f"failed to reach control endpoint on 127.0.0.1:{control_port}: {exc}", file=sys.stderr)
        return 1


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    args = _build_parser().parse_args(argv)

    logging.basicConfig(
        level=logging.WARNING - 10 * min(args.verbose, 2),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    if args.command == "override":
        return _run_override(args.fingerprint, args.control_port)

    config = Config(host=args.host, port=args.port)
    if args.ca_dir is not None:
        config.ca_dir = Path(args.ca_dir)
    if args.audit_log is not None:
        config.audit_log = Path(args.audit_log)
    if args.control_port is not None:
        config.control_port = args.control_port
    config.websocket_policy = args.websocket

    if args.command == "export-ca":
        return _run_export_ca(config, args.output)
    if args.command == "deploy-bundle":
        return _run_deploy_bundle(config, args.output_dir)

    print(f"windows-dlp-agent {__version__} - MITM DLP proxy on {config.host}:{config.port}")
    print(f"CA dir: {config.ca_dir}")
    if config.control_port is not None:
        print(f"override control endpoint enabled on port {config.control_port}")
    try:
        asyncio.run(run_proxy(config))
    except KeyboardInterrupt:
        print("\nshutting down")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
