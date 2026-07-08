from windows_dlp_agent import __version__
from windows_dlp_agent.__main__ import main


def test_version():
    assert __version__ == "0.1.0"


def test_main_runs():
    assert main([]) == 0
