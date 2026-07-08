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

from .audit import AuditLog, NullAuditLog
from .ca import CertificateAuthority
from .config import Config
from .control import ControlServer
from .dlp import Action, Decision, DlpEngine, default_engine
from .extract import extract_prompt, service_for_host
from .notify import Notifier, build_message, get_notifier
from .override import OverrideStore, fingerprint

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
        overrides: OverrideStore | None = None,
        audit: AuditLog | NullAuditLog | None = None,
    ):
        self.config = config or Config()
        self.ca = ca or CertificateAuthority.load_or_generate(self.config.ca_dir)
        self.engine = engine or default_engine(keywords=self.config.keywords)
        self.notifier = notifier or get_notifier()
        self.overrides = overrides or OverrideStore(self.config.override_ttl)
        if audit is not None:
            self.audit: AuditLog | NullAuditLog = audit
        elif self.config.audit_log is not None:
            self.audit = AuditLog(self.config.audit_log)
        else:
            self.audit = NullAuditLog()
        self._server: asyncio.AbstractServer | None = None
        self._control: ControlServer | None = None
        # SSL context for upstream WebSocket connections (httpx handles _forward's).
        self._ws_ssl_ctx = ssl.create_default_context()
        if not self.config.upstream_verify:
            self._ws_ssl_ctx.check_hostname = False
            self._ws_ssl_ctx.verify_mode = ssl.CERT_NONE
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
        if self.config.control_port is not None:
            self._control = ControlServer(self.overrides, port=self.config.control_port)
            await self._control.start()
            log.info("override control endpoint on 127.0.0.1:%s", self._control.port)
        return self._server

    async def serve_forever(self) -> None:
        server = self._server or await self.start()
        async with server:
            await server.serve_forever()

    async def aclose(self) -> None:
        if self._control is not None:
            await self._control.aclose()
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

            if _is_ws_upgrade(request.headers):
                # WebSocket upgrade — h11 can't proxy it; hand off per policy (§5).
                if self.config.websocket_policy == "block":
                    log.info("WebSocket blocked (fail-closed) to %s%s", host, path)
                    await self._send_block(conn, writer, Action.BLOCK, ["websocket"])
                    return
                trailing = conn.trailing_data[0]
                await self._relay_websocket(reader, writer, host, port, request, trailing)
                return

            decision, prompt = self._inspect(host, path, method, body)

            if self._should_forward(host, path, decision, prompt):
                await self._forward(conn, writer, host, port, method, path, headers, body)
            else:
                await self._send_block(conn, writer, decision.action, decision.categories)

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
    ) -> tuple[Decision, str | None]:
        if method not in ("POST", "PUT", "PATCH") or not body:
            return Decision(Action.ALLOW), None
        prompt = extract_prompt(host, path, body)
        if not prompt:
            if service_for_host(host):
                log.debug("no prompt extracted from %s%s (body %d bytes)", host, path, len(body))
            return Decision(Action.ALLOW), None
        if service_for_host(host):
            log.debug("extracted %d chars from %s%s: %r…", len(prompt), host, path, prompt[:80])
        decision = self.engine.evaluate(prompt)
        if decision.action is not Action.ALLOW:
            log.info(
                "DLP %s on %s%s: %s",
                decision.action.label, host, path,
                ", ".join(f"{f.detector}({f.preview()})" for f in decision.findings),
            )
        return decision, prompt

    def _should_forward(
        self, host: str, path: str, decision: Decision, prompt: str | None
    ) -> bool:
        """Apply policy (§4.3/§5). Returns True to forward, False to block.

        - ALLOW: forward.
        - WARN: block, unless the user granted a one-shot override for this exact
          content (warn-with-override) -> forward + audit the override.
        - BLOCK: always block (never overridable).
        """
        service = service_for_host(host)
        if decision.action is Action.ALLOW:
            return True

        if decision.action is Action.WARN and prompt is not None:
            fp = fingerprint(host, prompt)
            if self.overrides.consume(fp):
                log.info("override consumed for %s%s", host, path)
                self.audit.record_override(host=host, service=service, fingerprint=fp)
                self.audit.record_decision(
                    host=host, service=service, path=path,
                    decision=decision, outcome="allow-override",
                )
                return True

        # §5: do not forward; sensitive data never leaves the machine.
        self.audit.record_decision(
            host=host, service=service, path=path,
            decision=decision, outcome="block",
        )
        self._alert(decision, host, service)
        return False

    def _alert(self, decision: Decision, host: str, service: str | None) -> None:
        title, message = build_message(decision.categories, service, decision.action.label)
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
        """Forward the request and stream the response back chunk-by-chunk.

        Streaming (not buffering) so token-by-token replies (ChatGPT SSE) reach
        the browser as they arrive. Raw upstream bytes are relayed verbatim with
        the original content-encoding, re-framed to the client as HTTP/1.1
        chunked (or content-length 0 for bodyless responses).
        """
        url = _upstream_url(host, port, path)
        fwd_headers = [(k, v) for k, v in headers if k.lower() not in _HOP_BY_HOP]
        sent_headers = False
        try:
            async with self._client.stream(
                method, url, headers=fwd_headers, content=body or None
            ) as upstream:
                resp_headers = [
                    (k, v)
                    for k, v in upstream.headers.items()
                    if k.lower() not in _HOP_BY_HOP and k.lower() != "content-length"
                ]
                bodyless = (
                    method == "HEAD"
                    or upstream.status_code in (204, 304)
                    or upstream.status_code < 200
                )
                reason = upstream.reason_phrase.encode("latin-1")
                if bodyless:
                    resp_headers.append(("content-length", "0"))
                    writer.write(conn.send(h11.Response(
                        status_code=upstream.status_code, headers=resp_headers, reason=reason)))
                    writer.write(conn.send(h11.EndOfMessage()))
                    sent_headers = True
                    await writer.drain()
                    return
                resp_headers.append(("transfer-encoding", "chunked"))
                writer.write(conn.send(h11.Response(
                    status_code=upstream.status_code, headers=resp_headers, reason=reason)))
                sent_headers = True
                await writer.drain()
                async for chunk in upstream.aiter_raw():
                    if chunk:
                        writer.write(conn.send(h11.Data(data=chunk)))
                        await writer.drain()
                writer.write(conn.send(h11.EndOfMessage()))
                await writer.drain()
        except httpx.HTTPError as exc:
            log.debug("upstream error for %s: %s", url, exc)
            if not sent_headers:
                await self._send_bad_gateway(conn, writer)
            # else: partial response already streamed; caller tears the conn down

    async def _relay_websocket(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        host: str,
        port: int,
        request: h11.Request,
        trailing: bytes,
    ) -> None:
        """Blind-tunnel a WebSocket (fail-open, §5).

        We've terminated client TLS, so we open a fresh TLS connection to the
        upstream, replay the handshake, then pipe the decrypted byte streams both
        ways. Content is not inspected here (fail-open); because mainstream AI
        sites send the prompt via HTTP POST (which we do inspect), this is not a
        DLP gap for them. A future phase can parse WS frames here for DLP.
        """
        try:
            up_reader, up_writer = await asyncio.open_connection(
                host, port, ssl=self._ws_ssl_ctx, server_hostname=host
            )
        except (OSError, ssl.SSLError) as exc:
            log.debug("WebSocket upstream connect failed %s:%s: %s", host, port, exc)
            return
        log.info("WebSocket relayed (fail-open) to %s%s", host, request.target.decode("latin-1"))
        up_writer.write(_rebuild_request_bytes(request))
        if trailing:
            up_writer.write(trailing)
        try:
            await up_writer.drain()
            # Pipe both directions; when EITHER side closes, stop the other so we
            # don't deadlock waiting on a half-open connection.
            c2u = asyncio.create_task(_pipe(reader, up_writer))
            u2c = asyncio.create_task(_pipe(up_reader, writer))
            _done, pending = await asyncio.wait({c2u, u2c}, return_when=asyncio.FIRST_COMPLETED)
            for task in pending:
                task.cancel()
        except (ConnectionError, ssl.SSLError, OSError):
            pass
        finally:
            await _safe_close(up_writer)

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
        decision, prompt = self._inspect(host, target, method, body)
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
        if self._should_forward(host, target, decision, prompt):
            await self._forward(conn, writer, host, 443, method, target, headers, body)
        else:
            await self._send_block(conn, writer, decision.action, decision.categories)


def _upstream_url(host: str, port: int, path: str) -> str:
    """Build the upstream URL for a forwarded request.

    - Absolute-form target (`http://host/...`, the plain-HTTP proxy case, §3.1):
      used verbatim so we don't double the scheme.
    - Origin-form target (`/path`, from a decrypted CONNECT tunnel): composed
      into an https URL for `host` (with :port when non-default).
    """
    if path.startswith(("http://", "https://")):
        return path
    netloc = host if port == 443 else f"{host}:{port}"
    return f"https://{netloc}{path}"


def _is_ws_upgrade(headers: list[tuple[bytes, bytes]]) -> bool:
    """True if these request headers are a WebSocket upgrade handshake."""
    has_upgrade_ws = False
    has_conn_upgrade = False
    for k, v in headers:
        kl = k.decode("latin-1").lower()
        vl = v.decode("latin-1").lower()
        if kl == "upgrade" and "websocket" in vl:
            has_upgrade_ws = True
        elif kl == "connection" and "upgrade" in vl:
            has_conn_upgrade = True
    return has_upgrade_ws and has_conn_upgrade


def _rebuild_request_bytes(request: h11.Request) -> bytes:
    """Reconstruct the raw HTTP/1.1 request line + headers for replay upstream."""
    out = [request.method + b" " + request.target + b" HTTP/1.1\r\n"]
    for k, v in request.headers:
        out.append(k + b": " + v + b"\r\n")
    out.append(b"\r\n")
    return b"".join(out)


async def _pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    """Copy bytes one direction until EOF (used for WebSocket relay)."""
    try:
        while True:
            data = await reader.read(_CHUNK)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except (ConnectionError, ssl.SSLError, OSError):
        pass


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
