from __future__ import annotations

from typing import Self

import dns.message
import pytest

from dnstrace.engine import TraceEngine
from dnstrace.transports.doh import DoHTransport
from dnstrace.transports.dot import DoTTransport


class _FakeSSLObject:
    def version(self) -> str:
        return "TLSv1.3"

    def cipher(self) -> tuple[str, str, int]:
        return ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)

    def selected_alpn_protocol(self) -> str:
        return "dot"


class _FakeWriter:
    def get_extra_info(self, name: str) -> object | None:
        if name == "ssl_object":
            return _FakeSSLObject()
        return None


class _FakeStreamSocket:
    def __init__(self) -> None:
        self.writer = _FakeWriter()

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *exc_info: object) -> bool:
        return False


class _FakeBackend:
    async def make_socket(self, *args: object, **kwargs: object) -> _FakeStreamSocket:
        return _FakeStreamSocket()


@pytest.mark.asyncio
async def test_dot_transport_records_tls_timeline(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_tls(query, where, **kwargs):
        assert where == "1.1.1.1"
        assert kwargs["port"] == 853
        assert kwargs["server_hostname"] == "cloudflare-dns.com"
        assert kwargs["sock"] is not None
        return dns.message.make_response(query)

    monkeypatch.setattr("dnstrace.transports.dot.dns.asyncquery.tls", fake_tls)
    monkeypatch.setattr(
        "dnstrace.transports.dot.dns.asyncbackend.get_default_backend",
        lambda: _FakeBackend(),
    )
    transport = DoTTransport(
        "1.1.1.1",
        server_hostname="cloudflare-dns.com",
        verify=False,
    )

    result = await transport.query("example.com", "A")

    assert result.success is True
    assert result.rcode == "NOERROR"
    assert result.protocol == {
        "tls_version": "TLSv1.3",
        "cipher": "TLS_AES_256_GCM_SHA384",
        "alpn": "dot",
    }
    assert [event.name for event in result.events] == [
        "query.build",
        "tcp.connect",
        "tls.handshake.start",
        "tls.handshake.complete",
        "dns.receive",
    ]


class _FakeHTTPResponse:
    def __init__(self, content: bytes, http_version: str = "HTTP/2") -> None:
        self.status_code = 200
        self.content = content
        self.http_version = http_version
        self.extensions: dict[str, object] = {}


class _FakeAsyncClient:
    def __init__(self, *args: object, **kwargs: object) -> None:
        pass

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *exc_info: object) -> bool:
        return False

    async def post(self, url: str, **kwargs: object) -> _FakeHTTPResponse:
        query = dns.message.from_wire(kwargs["content"])
        response = dns.message.make_response(query)
        return _FakeHTTPResponse(response.to_wire())

    async def get(self, url: str, **kwargs: object) -> _FakeHTTPResponse:
        raise AssertionError("GET should not be used when post=True")


@pytest.mark.asyncio
async def test_doh_transport_uses_configured_endpoint(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("dnstrace.transports.doh.httpx.AsyncClient", _FakeAsyncClient)
    transport = DoHTransport("192.0.2.53", url="https://dns.example/dns-query")

    result = await transport.query("example.net", "AAAA")

    assert result.success is True
    assert result.rcode == "NOERROR"
    assert result.protocol["http_version"] == "HTTP/2"
    assert [event.name for event in result.events] == [
        "query.build",
        "https.request.start",
        "https.response",
    ]


def test_engine_builds_encrypted_transports() -> None:
    engine = TraceEngine(
        "1.1.1.1",
        dot_server_hostname="cloudflare-dns.com",
        doh_url="https://cloudflare-dns.com/dns-query",
    )

    assert isinstance(engine._build_transport("dot"), DoTTransport)
    assert isinstance(engine._build_transport("doh"), DoHTransport)
