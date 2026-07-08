"""Local explicit MITM proxy (spec §3).

Flow (§3.1):
    client -> CONNECT host:443 -> proxy 200 -> TLS terminate with forged leaf
    -> decrypt HTTP/1.1 (ALPN pinned, §3.4) -> extract prompt -> DLP
    -> hit: reply 451, never forward (§5) + toast
    -> clean: forward to real server via httpx, relay response back.

We pin ALPN to http/1.1 so the browser speaks HTTP/1.1 to us and we parse with
h11 — no HTTP/2 frame handling on the client side. Upstream may still be HTTP/2
(httpx handles it), decoupled from us.
"""

from __future__ import annotations

import asyncio
import logging
import ssl
from typing import Awaitable, Callable

import h11
import httpx

from .ca import CertificateAuthority
from .config import Config
from .dlp import Action, DlpEngine, default_engine
from .extract import extract_prompt, service_for_host
from .notify import Notifier, build_message, get_notifier

log = logging.getLogger("windows_dlp_agent.proxy")

# Headers we must not blindly forward upstream / back to client.
_HOP_BY_HOP = frozenset(
    h.lower()
    for h in (
        "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
        "te", "trailers", "transfer-encoding", "upgrade",
    )
)

_MAX_HEADER = 64 * 1024
_CHUNK = 64 * 1024


class MitmProxy:
    def __init__(
        self,
        config: Config | None = None,
        *,
        ca: CertificateAuthority | None = None,
        engine: DlpEngine | None = None,
        notifier: Notifier | None = None,
    ):
        self.config = config or Config()
        self.ca = ca or CertificateAuthority.load_or_generate(self.config.ca_dir)
        self.engine = engine or default_engine(keywords=self.config.keywords)
        self.notifier = notifier or get_notifier()
        self._server: asyncio.AbstractServer | None = None
        self._client = httpx.AsyncClient(
            http2=True,
            verify=self.config.upstream_verify,
            timeout=httpx.Timeout(30.0),
            follow_redirects=False,
        )

    # -- lifecycle ------------------------------------------------------------

    async def start(self) -> asyncio.AbstractServer:
        self._server = await asyncio.start_server(
            self._on_client, self.config.host, self.config.port
        )
        sockets = ", ".join(str(s.getsockname()) for s in self._server.sockets or [])
        log.info("MITM proxy listening on %s", sockets)
        return self._server

    async def serve_forever(self) -> None:
        server = self._server or await self.start()
        async with server:
            await server.serve_forever()

    async def aclose(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
        await self._client.aclose()

    @property
    def port(self) -> int:
        assert self._server and self._server.sockets
        return self._server.sockets[0].getsockname()[1]

    # -- connection handling --------------------------------------------------

    async def _on_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        try:
            request_line, headers = await self._read_request_head(reader)
            if request_line is None:
                return
            method, target, _version = request_line
            if method == "CONNECT":
                await self._handle_connect(reader, writer, target)
            else:
                await self._handle_plain(writer, method, target, headers, reader)
        except (ConnectionError, asyncio.IncompleteReadError, ssl.SSLError) as exc:
            log.debug("client %s dropped: %s", peer, exc)
        except Exception:  # noqa: BLE001
            log.exception("unexpected error handling %s", peer)
        finally:
            await _safe_close(writer)

    async def _read_request_head(
        self, reader: asyncio.StreamReader
    ) -> tuple[tuple[str, str, str] | None, list[tuple[str, str]]]:
        """Read raw request line + headers (used for the CONNECT preamble)."""
        try:
            head = await reader.readuntil(b"\r\n\r\n")
        except (asyncio.IncompleteReadError, asyncio.LimitOverrunError):
            return None, []
        lines = head.decode("latin-1").split("\r\n")
        parts = lines[0].split(" ")
        if len(parts) != 3:
            return None, []
        headers = []
        for line in lines[1:]:
            if not line or ":" not in line:
                continue
            k, v = line.split(":", 1)
            headers.append((k.strip(), v.strip()))
        return (parts[0], parts[1], parts[2]), headers

    async def _handle_connect(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, target: str
    ) -> None:
        host = target.rsplit(":", 1)[0]
        port = int(target.rsplit(":", 1)[1]) if ":" in target else 443

        writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await writer.drain()

        ctx = self.ca.context_for(host)
        try:
            await writer.start_tls(ctx)
        except ssl.SSLError as exc:
            log.debug("TLS handshake failed for %s: %s", host, exc)
            return

        await self._serve_decrypted(reader, writer, host, port)

    async def _serve_decrypted(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        host: str,
        port: int,
    ) -> None:
        """Handle HTTP/1.1 request(s) over the now-decrypted channel."""
        conn = h11.Connection(h11.SERVER)
        while True:
            request, body = await self._recv_h11_request(conn, reader)
            if request is None:
                return

            path = request.target.decode("latin-1")
            headers = [(k.decode("latin-1"), v.decode("latin-1")) for k, v in request.headers]
            method = request.method.decode("ascii")

            decision_action, categories = self._inspect(host, path, method, body)

            if decision_action >= Action.WARN:
                # §5: do not forward; sensitive data never leaves the machine.
                self._alert(categories, host, decision_action)
                await self._send_block(conn, writer, decision_action, categories)
            else:
                await self._forward(conn, writer, host, port, method, path, headers, body)

            if conn.our_state is h11.MUST_CLOSE or conn.their_state is h11.MUST_CLOSE:
                return
            try:
                conn.start_next_cycle()
            except h11.LocalProtocolError:
                return

    async def _recv_h11_request(
        self, conn: h11.Connection, reader: asyncio.StreamReader
    ) -> tuple[h11.Request | None, bytes]:
        body = bytearray()
        request: h11.Request | None = None
        while True:
            event = conn.next_event()
            if event is h11.NEED_DATA:
                data = await reader.read(_CHUNK)
                conn.receive_data(data)
                if not data:
                    # peer closed; let h11 surface ConnectionClosed next loop
                    if conn.their_state is h11.CLOSED:
                        return request, bytes(body)
                continue
            if isinstance(event, h11.Request):
                request = event
            elif isinstance(event, h11.Data):
                body += event.data
            elif isinstance(event, h11.EndOfMessage):
                return request, bytes(body)
            elif isinstance(event, h11.ConnectionClosed) or event is h11.PAUSED:
                return request, bytes(body)

    # -- DLP + actions --------------------------------------------------------

    def _inspect(
        self, host: str, path: str, method: str, body: bytes
    ) -> tuple[Action, list[str]]:
        if method not in ("POST", "PUT", "PATCH") or not body:
            return Action.ALLOW, []
        prompt = extract_prompt(host, path, body)
        if not prompt:
            return Action.ALLOW, []
        decision = self.engine.evaluate(prompt)
        if decision.action is Action.ALLOW:
            return Action.ALLOW, []
        log.info(
            "DLP %s on %s%s: %s",
            decision.action.label, host, path,
            ", ".join(f"{f.detector}({f.preview()})" for f in decision.findings),
        )
        return decision.action, decision.categories

    def _alert(self, categories: list[str], host: str, action: Action) -> None:
        service = service_for_host(host)
        title, message = build_message(categories, service, action.label)
        try:
            self.notifier.notify(title, message)
        except Exception:  # noqa: BLE001 -- never let a toast failure break the proxy
            log.exception("notifier failed")

    async def _send_block(
        self,
        conn: h11.Connection,
        writer: asyncio.StreamWriter,
        action: Action,
        categories: list[str],
    ) -> None:
        kinds = "、".join(categories) if categories else "sensitive data"
        payload = (
            f"Request blocked by Windows DLP Agent.\r\n"
            f"Detected: {kinds}\r\n"
        ).encode("utf-8")
        headers = [
            ("content-type", "text/plain; charset=utf-8"),
            ("content-length", str(len(payload))),
            ("connection", "close"),
            ("x-dlp-action", action.label),
        ]
        writer.write(conn.send(h11.Response(status_code=451, headers=headers, reason=b"Blocked")))
        writer.write(conn.send(h11.Data(data=payload)))
        writer.write(conn.send(h11.EndOfMessage()))
        await writer.drain()

    async def _forward(
        self,
        conn: h11.Connection,
        writer: asyncio.StreamWriter,
        host: str,
        port: int,
        method: str,
        path: str,
        headers: list[tuple[str, str]],
        body: bytes,
    ) -> None:
        netloc = host if port == 443 else f"{host}:{port}"
        url = f"https://{netloc}{path}"
        fwd_headers = [(k, v) for k, v in headers if k.lower() not in _HOP_BY_HOP]
        try:
            upstream = await self._client.request(
                method, url, headers=fwd_headers, content=body or None
            )
        except httpx.HTTPError as exc:
            log.debug("upstream error for %s: %s", url, exc)
            await self._send_bad_gateway(conn, writer)
            return

        resp_headers = [
            (k, v) for k, v in upstream.headers.items() if k.lower() not in _HOP_BY_HOP
        ]
        content = upstream.content
        # Normalise framing: we send an explicit content-length ourselves.
        resp_headers = [(k, v) for k, v in resp_headers if k.lower() != "content-length"]
        resp_headers.append(("content-length", str(len(content))))
        writer.write(
            conn.send(
                h11.Response(
                    status_code=upstream.status_code,
                    headers=resp_headers,
                    reason=upstream.reason_phrase.encode("latin-1"),
                )
            )
        )
        writer.write(conn.send(h11.Data(data=content)))
        writer.write(conn.send(h11.EndOfMessage()))
        await writer.drain()

    async def _send_bad_gateway(self, conn: h11.Connection, writer: asyncio.StreamWriter) -> None:
        payload = b"upstream unavailable"
        headers = [
            ("content-type", "text/plain"),
            ("content-length", str(len(payload))),
            ("connection", "close"),
        ]
        writer.write(conn.send(h11.Response(status_code=502, headers=headers, reason=b"Bad Gateway")))
        writer.write(conn.send(h11.Data(data=payload)))
        writer.write(conn.send(h11.EndOfMessage()))
        await writer.drain()

    # -- plain HTTP (rare; AI sites are HTTPS) ---------------------------------

    async def _handle_plain(
        self,
        writer: asyncio.StreamWriter,
        method: str,
        target: str,
        headers: list[tuple[str, str]],
        reader: asyncio.StreamReader,
    ) -> None:
        # Absolute-URI request: read any body by content-length, inspect, forward.
        length = 0
        for k, v in headers:
            if k.lower() == "content-length":
                try:
                    length = int(v)
                except ValueError:
                    length = 0
        body = await reader.readexactly(length) if length > 0 else b""

        from .extract import host_from_url

        host = host_from_url(target)
        action, categories = self._inspect(host, target, method, body)
        conn = h11.Connection(h11.SERVER)
        # Prime h11 with a synthetic request so response framing is valid.
        conn.receive_data(
            f"{method} {target} HTTP/1.1\r\nhost: {host}\r\ncontent-length: {len(body)}\r\n\r\n".encode()
            + body
        )
        # drain events
        while True:
            ev = conn.next_event()
            if isinstance(ev, h11.EndOfMessage) or ev is h11.NEED_DATA:
                break
        if action >= Action.WARN:
            self._alert(categories, host, action)
            await self._send_block(conn, writer, action, categories)
        else:
            await self._forward(conn, writer, host, 443, method, target, headers, body)


ClientHandler = Callable[[asyncio.StreamReader, asyncio.StreamWriter], Awaitable[None]]


async def _safe_close(writer: asyncio.StreamWriter) -> None:
    try:
        if not writer.is_closing():
            writer.close()
        await writer.wait_closed()
    except (ConnectionError, ssl.SSLError, OSError):
        pass


async def run(config: Config | None = None) -> None:
    proxy = MitmProxy(config)
    try:
        await proxy.serve_forever()
    finally:
        await proxy.aclose()
