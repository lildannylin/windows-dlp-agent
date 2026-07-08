# windows-dlp-agent

A Windows Data Loss Prevention (DLP) agent.

## Requirements

- Python 3.10+
- Windows 10/11

## Setup

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
```

## Running

Start the local MITM DLP proxy (spec §3), with an audit log and the override
control endpoint enabled:

```powershell
python -m windows_dlp_agent --port 8080 --audit-log dlp-audit.jsonl --control-port 8081
```

Export the root CA so it can be installed into the endpoint's Trusted Root
store (spec §6), then point the browser proxy at `127.0.0.1:8080`:

```powershell
python -m windows_dlp_agent export-ca root-ca.crt
```

Generate a full deployment bundle — Chrome/Edge managed-proxy `.reg` policy,
the root CA, and an `install.ps1` (spec §6). Push it via GPO / Intune / MDM:

```powershell
python -m windows_dlp_agent deploy-bundle .\bundle
```

Grant a one-shot **warn-with-override** (§5) for a blocked prompt, using the
fingerprint from the audit log / toast, against the running proxy's control port:

```powershell
python -m windows_dlp_agent override <fingerprint> --control-port 8081
```

Responses stream back chunk-by-chunk (so token-by-token AI replies aren't
buffered). WebSocket connections are **relayed** (fail-open) by default so sites
keep working; the user's prompt to mainstream AI sites goes via HTTP POST which
is still inspected. Use `--websocket block` for a fail-closed policy that refuses
WebSocket upgrades (stricter, but breaks WS-based apps).

Use `-v` / `-vv` for info / debug logging.

## Testing

```powershell
pytest
```

## Design

See [`docs/spec.md`](docs/spec.md) for the full implementation spec.

Modules:

| Module | Spec | Purpose |
|---|---|---|
| `dlp/` | §4 | Layered detection engine (regex + checksums + entropy + keywords), precision-tiered actions |
| `ca.py` | §3.2 | Root CA load/generate + per-host forged leaf certs, ALPN-pinned server contexts |
| `extract.py` | §4.4 | Pull the AI prompt out of intercepted request bodies (ChatGPT/Claude/Gemini + generic) |
| `proxy.py` | §3.1/§5 | asyncio explicit MITM proxy: CONNECT, TLS terminate, DLP hook, block (451) or streamed forward; WebSocket relay/block |
| `notify.py` | §5 | Windows toast on a hit (no-op fallback off-Windows) |
| `override.py` | §5 | One-shot, TTL-bounded warn-with-override keyed by content fingerprint |
| `control.py` | §5 | Loopback control endpoint to grant overrides |
| `audit.py` | §5 | Append-only JSONL audit of decisions + overrides (masked, never raw secrets) |
| `deploy.py` | §6 | Generate Chrome/Edge proxy policy `.reg`, CA-trust command, `install.ps1` |
| `service.py` | §6 | Run as a Windows service (NSSM/sc.exe, or native pywin32) |

## Project layout

```
windows-dlp-agent/
├── src/windows_dlp_agent/   # application package
├── tests/                   # test suite
├── pyproject.toml           # project metadata & dependencies
└── README.md
```
