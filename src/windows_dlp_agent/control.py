"""Loopback control endpoint for granting overrides (spec §5).

A WARN hit is blocked and the user is offered "send anyway". Acting on that
(a toast button, tray app, or the `override` CLI) POSTs the fingerprint here;
the proxy then lets the one-shot resend through. Bound to 127.0.0.1 only.
"""

from __future__ import annotations

import asyncio
import json
import logging

from .override import OverrideStore

log = logging.getLogger("windows_dlp_agent.control")

__all__ = ["ControlServer"]


class ControlServer:
    """Tiny HTTP/1.1 server exposing POST /override {"fingerprint": "..."}."""

    def __init__(self, overrides: OverrideStore, host: str = "127.0.0.1", port: int = 0):
        self._overrides = overrides
        self._host = host
        self._port = port
        self._server: asyncio.AbstractServer | None = None

    async def start(self) -> asyncio.AbstractServer:
        self._server = await asyncio.start_server(self._handle, self._host, self._port)
        log.info("control endpoint on %s", self.port)
        return self._server

    async def aclose(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()

    @property
    def port(self) -> int:
        assert self._server and self._server.sockets
        return self._server.sockets[0].getsockname()[1]

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            head = await reader.readuntil(b"\r\n\r\n")
        except (asyncio.IncompleteReadError, asyncio.LimitOverrunError):
            writer.close()
            return
        lines = head.decode("latin-1").split("\r\n")
        request_line = lines[0].split(" ")
        length = 0
        for line in lines[1:]:
            if line.lower().startswith("content-length:"):
                try:
                    length = int(line.split(":", 1)[1].strip())
                except ValueError:
                    length = 0
        body = await reader.readexactly(length) if length > 0 else b""

        status, payload = self._route(request_line, body)
        writer.write(
            b"HTTP/1.1 " + status + b"\r\n"
            b"content-type: application/json\r\n"
            b"content-length: " + str(len(payload)).encode() + b"\r\n"
            b"connection: close\r\n\r\n" + payload
        )
        try:
            await writer.drain()
        except ConnectionError:
            pass
        writer.close()

    def _route(self, request_line: list[str], body: bytes) -> tuple[bytes, bytes]:
        if len(request_line) < 2:
            return b"400 Bad Request", b'{"error":"bad request"}'
        method, target = request_line[0], request_line[1]
        if method == "POST" and target.split("?")[0] == "/override":
            try:
                data = json.loads(body or b"{}")
                fp = data["fingerprint"]
            except (ValueError, KeyError, TypeError):
                return b"400 Bad Request", b'{"error":"fingerprint required"}'
            self._overrides.grant(fp)
            log.info("override granted for %s", fp[:12])
            return b"200 OK", b'{"status":"granted"}'
        return b"404 Not Found", b'{"error":"not found"}'
