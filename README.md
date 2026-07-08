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

```powershell
python -m windows_dlp_agent
```

## Testing

```powershell
pytest
```

## Project layout

```
windows-dlp-agent/
├── src/windows_dlp_agent/   # application package
├── tests/                   # test suite
├── pyproject.toml           # project metadata & dependencies
└── README.md
```
