"""Deployment artifacts for enforcing the proxy on endpoints (spec §6).

Generates:
    * a Windows registry (.reg) file that pins Chrome + Edge to the local proxy
      via managed policy (ProxyMode=fixed_servers) so users can't change it,
    * the certutil command to trust the root CA in the machine store,
    * a PowerShell install script that applies the policy, trusts the CA, and
      registers the background service.

Pushing the .reg / policy via GPO / Intune / MDM is what makes it unbypassable.
"""

from __future__ import annotations

from pathlib import Path

from .config import Config

__all__ = [
    "proxy_policy_reg",
    "install_ca_command",
    "service_install_commands",
    "install_script",
    "write_bundle",
]

# Chrome and Edge both read managed proxy policy from these keys.
_POLICY_KEYS = {
    "Chrome": r"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome",
    "Edge": r"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge",
}

# Hosts that must NOT go through the proxy (local/loopback), so the control
# endpoint and local services keep working.
_DEFAULT_BYPASS = ["localhost", "127.0.0.1", "<local>"]


def proxy_policy_reg(config: Config, *, bypass: list[str] | None = None) -> str:
    """.reg content pinning Chrome + Edge to host:port via fixed_servers (§6)."""
    server = f"{config.host}:{config.port}"
    bypass_list = ";".join(bypass if bypass is not None else _DEFAULT_BYPASS)
    lines = ["Windows Registry Editor Version 5.00", ""]
    for key in _POLICY_KEYS.values():
        lines.append(f"[{key}]")
        lines.append('"ProxyMode"="fixed_servers"')
        lines.append(f'"ProxyServer"="{server}"')
        lines.append(f'"ProxyBypassList"="{bypass_list}"')
        lines.append("")
    return "\r\n".join(lines)


def install_ca_command(cert_path: str | Path) -> str:
    """certutil command to add the root CA to the machine Trusted Root store."""
    return f'certutil -addstore -f Root "{cert_path}"'


def service_install_commands(
    python_exe: str | Path,
    *,
    service_name: str = "WindowsDLPAgent",
    port: int = 8080,
    ca_dir: str | Path | None = None,
    nssm: bool = True,
) -> list[str]:
    """Commands to register the proxy as an auto-start service (§6).

    Uses NSSM by default (simplest way to daemonize a Python script with
    auto-restart); set nssm=False for a bare `sc.exe` registration.
    """
    args = f"-m windows_dlp_agent --port {port}"
    if ca_dir is not None:
        args += f' --ca-dir "{ca_dir}"'
    if nssm:
        return [
            f'nssm install {service_name} "{python_exe}" {args}',
            f"nssm set {service_name} Start SERVICE_AUTO_START",
            f"nssm set {service_name} AppExit Default Restart",
            f"nssm start {service_name}",
        ]
    bin_path = f'"{python_exe}" {args}'
    return [
        f'sc.exe create {service_name} binPath= "{bin_path}" start= auto',
        f"sc.exe start {service_name}",
    ]


def install_script(
    config: Config,
    *,
    cert_filename: str = "proxy-ca.crt",
    reg_filename: str = "proxy-policy.reg",
    service_name: str = "WindowsDLPAgent",
) -> str:
    """PowerShell installer that trusts the CA, applies policy, starts service."""
    cmds = service_install_commands(
        "python", service_name=service_name, port=config.port, ca_dir=config.ca_dir
    )
    service_block = "\n".join(cmds)
    cert_here = "$here\\" + cert_filename
    ca_cmd = install_ca_command(cert_here)
    return f"""# Windows DLP Agent installer (spec section 6). Run as Administrator.
$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host "Trusting root CA..."
{ca_cmd}

Write-Host "Applying Chrome/Edge proxy policy..."
reg.exe import "$here\\{reg_filename}"

Write-Host "Registering background service..."
{service_block}

Write-Host "Done. Browsers are pinned to {config.host}:{config.port}."
"""


def write_bundle(out_dir: str | Path, config: Config, cert_pem: bytes) -> dict[str, Path]:
    """Write the full deploy bundle (reg + CA cert + install.ps1) to out_dir."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    reg_path = out / "proxy-policy.reg"
    cert_path = out / "proxy-ca.crt"
    ps1_path = out / "install.ps1"
    reg_path.write_text(proxy_policy_reg(config), encoding="utf-8")
    cert_path.write_bytes(cert_pem)
    ps1_path.write_text(install_script(config), encoding="utf-8")
    return {"reg": reg_path, "cert": cert_path, "script": ps1_path}
