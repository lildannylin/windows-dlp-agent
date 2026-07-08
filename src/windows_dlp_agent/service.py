"""Windows service integration (spec §6).

Two supported ways to run the proxy as an always-on, auto-restart service:

    1. NSSM / sc.exe wrapping `python -m windows_dlp_agent` -- see deploy.py
       (`service_install_commands`). This is the recommended, dependency-free
       path and is what the generated installer uses.
    2. A native pywin32 service (this module's `DlpAgentService`), used only
       when pywin32 is installed. Register with:
           python -m windows_dlp_agent.service install
           python -m windows_dlp_agent.service start

`run_service()` is the plain entry the service host calls; it runs the proxy
event loop until stopped.
"""

from __future__ import annotations

import asyncio

from .config import Config
from .proxy import MitmProxy

__all__ = ["run_service", "DlpAgentService"]


async def _serve(config: Config, stop: asyncio.Event) -> None:
    proxy = MitmProxy(config)
    server = await proxy.start()
    try:
        async with server:
            serving = asyncio.create_task(server.serve_forever())
            await stop.wait()
            serving.cancel()
    finally:
        await proxy.aclose()


def run_service(config: Config | None = None) -> None:
    """Run the proxy until the process is asked to stop (blocking)."""
    config = config or Config()
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    stop = asyncio.Event()
    try:
        loop.run_until_complete(_serve(config, stop))
    except KeyboardInterrupt:
        stop.set()
    finally:
        loop.close()


try:  # pragma: no cover - only importable on Windows with pywin32 present
    import servicemanager  # type: ignore
    import win32service  # type: ignore
    import win32serviceutil  # type: ignore

    class DlpAgentService(win32serviceutil.ServiceFramework):  # type: ignore
        _svc_name_ = "WindowsDLPAgent"
        _svc_display_name_ = "Windows DLP Agent"
        _svc_description_ = "Local MITM DLP proxy that inspects AI prompts (spec section 3)."

        def __init__(self, args):
            super().__init__(args)
            self._loop = asyncio.new_event_loop()
            self._stop = None

        def SvcStop(self):  # noqa: N802 - pywin32 API name
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            if self._stop is not None:
                self._loop.call_soon_threadsafe(self._stop.set)

        def SvcDoRun(self):  # noqa: N802 - pywin32 API name
            asyncio.set_event_loop(self._loop)
            self._stop = asyncio.Event()
            servicemanager.LogInfoMsg("Windows DLP Agent starting")
            self._loop.run_until_complete(_serve(Config(), self._stop))

    def _service_main() -> None:
        win32serviceutil.HandleCommandLine(DlpAgentService)

except ImportError:  # pywin32 not available (non-Windows / not installed)
    DlpAgentService = None  # type: ignore

    def _service_main() -> None:
        raise SystemExit(
            "pywin32 is required for the native service. Install it, or use the "
            "NSSM/sc.exe commands from windows_dlp_agent.deploy instead."
        )


if __name__ == "__main__":
    _service_main()
