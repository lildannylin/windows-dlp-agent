import pytest

from windows_dlp_agent import __version__
from windows_dlp_agent.__main__ import main


def test_version():
    assert __version__ == "0.1.0"


def test_version_flag_exits_zero(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert __version__ in capsys.readouterr().out


def test_export_ca_writes_cert(tmp_path):
    out = tmp_path / "root.crt"
    rc = main(["--ca-dir", str(tmp_path / "ca"), "export-ca", str(out)])
    assert rc == 0
    assert out.exists()
    assert b"BEGIN CERTIFICATE" in out.read_bytes()
