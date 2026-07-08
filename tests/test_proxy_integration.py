"""End-to-end MITM proxy test (spec sections 3/5/8).

Drives a real TLS client through the proxy using the proxy's own CA, against a
local TLS 'upstream' echo server. Verifies:
    * clean prompt is forwarded and the upstream response comes back,
    * a fake card / API key is blocked (451) and never reaches upstream,
    * a desktop toast is emitted on the hit (recorded notifier).
"""

from __future__ import annotations

import asyncio
import ssl
import tempfile
from pathlib import Path

import h11
import pytest

from windows_dlp_agent.ca import CertificateAuthority
from windows_dlp_agent.config import Config
from windows_dlp_agent.extract import register_service
from windows_dlp_agent.notify import RecordingNotifier
from windows_dlp_agent.proxy import MitmProxy

# The local test upstream is reached via CONNECT 127.0.0.1:<port>, so the proxy
# sees host "127.0.0.1". DLP only inspects recognized AI destinations, so we
# register the loopback host as an AI service (generic sweep) for these tests.
register_service("127.0.0.1", "TestAI")


class _Upstream:
    """Minimal HTTPS/1.1 echo server that records what it received."""

    def __init__(self, ca: CertificateAuthority):
        self._ctx = ca.context_for("127.0.0.1")
        self.hits: list[bytes] = []
        self.server: asyncio.AbstractServer | None = None
        self.port: int = 0

    async def start(self) -> int:
        self.server = await asyncio.start_server(
            self._handle, "127.0.0.1", 0, ssl=self._ctx
        )
        self.port = self.server.sockets[0].getsockname()[1]
        return self.port

    async def stop(self) -> None:
        if self.server:
            self.server.close()
            await self.server.wait_closed()

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        conn = h11.Connection(h11.SERVER)
        body = bytearray()
        while True:
            event = conn.next_event()
            if event is h11.NEED_DATA:
                conn.receive_data(await reader.read(65536))
                continue
            if isinstance(event, h11.Data):
                body += event.data
            elif isinstance(event, h11.EndOfMessage):
                break
            elif isinstance(event, h11.ConnectionClosed):
                writer.close()
                return
        self.hits.append(bytes(body))
        payload = b"upstream-ok"
        writer.write(conn.send(h11.Response(status_code=200, headers=[
            ("content-type", "text/plain"),
            ("content-length", str(len(payload))),
        ])))
        writer.write(conn.send(h11.Data(data=payload)))
        writer.write(conn.send(h11.EndOfMessage()))
        await writer.drain()
        writer.close()


async def _proxy_roundtrip(proxy_port: int, ca: CertificateAuthority, upstream_port: int,
                           body: bytes) -> tuple[int, bytes]:
    """Send one POST through the proxy via CONNECT; return (status, body)."""
    reader, writer = await asyncio.open_connection("127.0.0.1", proxy_port)
    writer.write(f"CONNECT 127.0.0.1:{upstream_port} HTTP/1.1\r\n\r\n".encode())
    await writer.drain()
    line = await reader.readuntil(b"\r\n\r\n")
    assert b"200" in line, line

    client_ctx = ssl.create_default_context()
    with tempfile.NamedTemporaryFile("wb", suffix=".crt", delete=False) as f:
        f.write(ca.cert_pem())
        ca_file = f.name
    try:
        client_ctx.load_verify_locations(ca_file)
        await writer.start_tls(client_ctx, server_hostname="127.0.0.1")

        conn = h11.Connection(h11.CLIENT)
        writer.write(conn.send(h11.Request(
            method="POST",
            target="/backend-api/conversation",
            headers=[
                ("host", "127.0.0.1"),
                ("content-type", "application/json"),
                ("content-length", str(len(body))),
            ],
        )))
        writer.write(conn.send(h11.Data(data=body)))
        writer.write(conn.send(h11.EndOfMessage()))
        await writer.drain()

        status = None
        resp_body = bytearray()
        while True:
            event = conn.next_event()
            if event is h11.NEED_DATA:
                data = await reader.read(65536)
                conn.receive_data(data)
                if not data:
                    break
                continue
            if isinstance(event, h11.Response):
                status = event.status_code
            elif isinstance(event, h11.Data):
                resp_body += event.data
            elif isinstance(event, (h11.EndOfMessage, h11.ConnectionClosed)):
                break
        return status, bytes(resp_body)
    finally:
        Path(ca_file).unlink(missing_ok=True)
        writer.close()
        try:
            await writer.wait_closed()
        except (ConnectionError, ssl.SSLError, OSError):
            pass


@pytest.fixture
async def stack(tmp_path):
    ca = CertificateAuthority.generate()
    upstream = _Upstream(ca)
    await upstream.start()

    notifier = RecordingNotifier()
    config = Config(host="127.0.0.1", port=0, ca_dir=tmp_path / "ca", upstream_verify=False)
    proxy = MitmProxy(config, ca=ca, notifier=notifier)
    await proxy.start()

    yield proxy, ca, upstream, notifier

    await proxy.aclose()
    await upstream.stop()


import json  # noqa: E402


def _chatgpt_body(prompt: str) -> bytes:
    return json.dumps({"messages": [{"content": {"parts": [prompt]}}]}).encode()


async def test_clean_prompt_is_forwarded(stack):
    proxy, ca, upstream, notifier = stack
    status, resp = await _proxy_roundtrip(
        proxy.port, ca, upstream.port,
        _chatgpt_body("What is the capital of France?"),
    )
    assert status == 200
    assert resp == b"upstream-ok"
    assert len(upstream.hits) == 1  # request actually reached upstream
    assert notifier.messages == []


async def test_fake_card_is_blocked(stack):
    proxy, ca, upstream, notifier = stack
    status, resp = await _proxy_roundtrip(
        proxy.port, ca, upstream.port,
        _chatgpt_body("my card is 4111 1111 1111 1111"),
    )
    assert status == 451
    assert b"blocked" in resp.lower()
    assert upstream.hits == []  # never left the machine (section 5)
    assert len(notifier.messages) == 1
    assert "financial" in notifier.messages[0][1]


async def test_api_key_is_blocked(stack):
    proxy, ca, upstream, notifier = stack
    status, _resp = await _proxy_roundtrip(
        proxy.port, ca, upstream.port,
        _chatgpt_body("key sk-abcdefghijklmnopqrstuvwxyz0123"),
    )
    assert status == 451
    assert upstream.hits == []
    assert len(notifier.messages) == 1


# --- warn-with-override (section 5) -----------------------------------------


async def _grant_override(control_port: int, fp: str) -> int:
    reader, writer = await asyncio.open_connection("127.0.0.1", control_port)
    body = json.dumps({"fingerprint": fp}).encode()
    writer.write(
        b"POST /override HTTP/1.1\r\n"
        b"host: 127.0.0.1\r\n"
        b"content-type: application/json\r\n"
        b"content-length: " + str(len(body)).encode() + b"\r\n\r\n" + body
    )
    await writer.drain()
    line = await reader.readuntil(b"\r\n")
    writer.close()
    return int(line.split(b" ")[1])


async def test_warn_blocks_then_override_forwards(tmp_path):
    from windows_dlp_agent.control import ControlServer
    from windows_dlp_agent.override import OverrideStore, fingerprint

    ca = CertificateAuthority.generate()
    upstream = _Upstream(ca)
    await upstream.start()
    overrides = OverrideStore(ttl_seconds=300)
    notifier = RecordingNotifier()
    config = Config(host="127.0.0.1", port=0, ca_dir=tmp_path / "ca", upstream_verify=False)
    proxy = MitmProxy(config, ca=ca, notifier=notifier, overrides=overrides)
    await proxy.start()
    control = ControlServer(overrides, port=0)
    await control.start()

    try:
        prompt = "please email me at alice@example.com"
        body = _chatgpt_body(prompt)

        # 1) WARN hit is blocked first, toast emitted, nothing forwarded.
        status, _ = await _proxy_roundtrip(proxy.port, ca, upstream.port, body)
        assert status == 451
        assert upstream.hits == []
        assert len(notifier.messages) == 1

        # 2) User approves via the control endpoint.
        fp = fingerprint("127.0.0.1", prompt)
        assert await _grant_override(control.port, fp) == 200

        # 3) Same content now forwards exactly once (one-shot override).
        status, resp = await _proxy_roundtrip(proxy.port, ca, upstream.port, body)
        assert status == 200
        assert resp == b"upstream-ok"
        assert len(upstream.hits) == 1

        # 4) A further resend is blocked again (grant was one-shot).
        status, _ = await _proxy_roundtrip(proxy.port, ca, upstream.port, body)
        assert status == 451
        assert len(upstream.hits) == 1
    finally:
        await control.aclose()
        await proxy.aclose()
        await upstream.stop()


async def test_block_tier_cannot_be_overridden(tmp_path):
    from windows_dlp_agent.override import OverrideStore, fingerprint

    ca = CertificateAuthority.generate()
    upstream = _Upstream(ca)
    await upstream.start()
    overrides = OverrideStore(ttl_seconds=300)
    config = Config(host="127.0.0.1", port=0, ca_dir=tmp_path / "ca", upstream_verify=False)
    proxy = MitmProxy(config, ca=ca, notifier=RecordingNotifier(), overrides=overrides)
    await proxy.start()

    try:
        prompt = "my card 4111 1111 1111 1111"
        overrides.grant(fingerprint("127.0.0.1", prompt))  # pre-granted, must be ignored
        status, _ = await _proxy_roundtrip(proxy.port, ca, upstream.port, _chatgpt_body(prompt))
        assert status == 451  # BLOCK tier ignores overrides
        assert upstream.hits == []
    finally:
        await proxy.aclose()
        await upstream.stop()

