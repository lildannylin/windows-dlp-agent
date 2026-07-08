"""Tests for deployment artifact generation (spec §6)."""

from __future__ import annotations

from windows_dlp_agent.config import Config
from windows_dlp_agent.deploy import (
    install_ca_command,
    proxy_policy_reg,
    service_install_commands,
    write_bundle,
)


def test_proxy_policy_reg_pins_chrome_and_edge():
    reg = proxy_policy_reg(Config(host="127.0.0.1", port=8080))
    assert "Windows Registry Editor Version 5.00" in reg
    assert r"SOFTWARE\Policies\Google\Chrome" in reg
    assert r"SOFTWARE\Policies\Microsoft\Edge" in reg
    assert '"ProxyMode"="fixed_servers"' in reg
    assert '"ProxyServer"="127.0.0.1:8080"' in reg
    assert "localhost" in reg  # bypass list keeps loopback direct


def test_proxy_policy_custom_bypass():
    reg = proxy_policy_reg(Config(port=9999), bypass=["intranet.local"])
    assert "intranet.local" in reg
    assert '"ProxyServer"="127.0.0.1:9999"' in reg


def test_install_ca_command():
    cmd = install_ca_command("C:/certs/proxy-ca.crt")
    assert "certutil" in cmd
    assert "Root" in cmd
    assert "proxy-ca.crt" in cmd


def test_service_install_commands_nssm_and_sc():
    nssm = service_install_commands("C:/py/python.exe", port=8080)
    assert any("nssm install WindowsDLPAgent" in c for c in nssm)
    assert any("--port 8080" in c for c in nssm)

    sc = service_install_commands("C:/py/python.exe", port=8080, nssm=False)
    assert any(c.startswith("sc.exe create") for c in sc)


def test_write_bundle(tmp_path):
    paths = write_bundle(tmp_path / "bundle", Config(port=8080), b"-----BEGIN CERTIFICATE-----\n")
    assert paths["reg"].exists()
    assert paths["cert"].exists()
    assert paths["script"].exists()
    assert "fixed_servers" in paths["reg"].read_text(encoding="utf-8")
    assert paths["script"].read_text(encoding="utf-8").startswith("# Windows DLP Agent installer")
    assert b"BEGIN CERTIFICATE" in paths["cert"].read_bytes()
