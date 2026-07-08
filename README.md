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

Start the local MITM DLP proxy (spec §3):

```powershell
python -m windows_dlp_agent --port 8080
```

Export the root CA so it can be installed into the endpoint's Trusted Root
store (spec §6), then point the browser proxy at `127.0.0.1:8080`:

```powershell
python -m windows_dlp_agent export-ca root-ca.crt
```

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
| `extract.py` | §4.4 | Pull the AI prompt out of intercepted request bodies (ChatGPT/Claude + generic) |
| `proxy.py` | §3.1/§5 | asyncio explicit MITM proxy: CONNECT, TLS terminate, DLP hook, block (451) or forward |
| `notify.py` | §5 | Windows toast on a hit (no-op fallback off-Windows) |

## Project layout

```
windows-dlp-agent/
├── src/windows_dlp_agent/   # application package
├── tests/                   # test suite
├── pyproject.toml           # project metadata & dependencies
└── README.md
```
