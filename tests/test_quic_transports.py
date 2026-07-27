from __future__ import annotations

from types import SimpleNamespace
from typing import Self

import dns.message
import dns.query
import pytest
from dns.quic._common import UnexpectedEOF

from dnstrace.engine import TraceEngine
from dnstrace.transports.doh3 import DoH3Transport
from dnstrace.transports.doq import DoQTransport


class _FakeQuicConnection:
    def __init__(self, alpn: str) -> None:
        self._connection = SimpleNamespace(tls=SimpleNamespace(alpn_negotiated=alpn))


def _fake_manager_factory(alpn: str, captured: dict[str, object] | None = None) -> type:
    class _FakeManager:
        def __init__(self, *args: object, **kwargs: object) -> None:
            if captured is not None:
                captured.update(kwargs)

        def connect(self, address: str, port: int, source=None, source_port=0):
            return _FakeQuicConnection(alpn)

        async def __aenter__(self) -> Self:
            return self

        async def __aexit__(self, *exc_info: object) -> bool:
            return False

    return _FakeManager


@pytest.mark.asyncio
async def test_doq_query_records_quic_timeline(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, object] = {}

    async def fake_quic(message, where, **kwargs):
        captured.update(where=where, **kwargs)
        return dns.message.make_response(message)

    monkeypatch.setattr("dns.asyncquery.quic", fake_quic)
    monkeypatch.setattr(
        "dnstrace.transports.doq.dns.quic.AsyncioQuicManager", _fake_manager_factory("doq")
    )
    transport = DoQTransport(
        "192.0.2.53",
        port=8853,
        server_hostname="resolver.example",
        verify=False,
    )

    result = await transport.query("example.com", "A")

    assert result.success is True
    assert result.transport == "doq"
    assert captured["where"] == "192.0.2.53"
    assert captured["port"] == 8853
    assert captured["server_hostname"] == "resolver.example"
    assert result.protocol == {"alpn": "doq", "tls_version": "TLSv1.3"}
    assert [event.name for event in result.events] == [
        "query.build",
        "quic.handshake.start",
        "quic.handshake.complete",
        "quic.stream.receive",
    ]


@pytest.mark.asyncio
async def test_doh3_forces_http3(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, object] = {}

    async def fake_https(message, where, **kwargs):
        captured.update(where=where, **kwargs)
        return dns.message.make_response(message)

    monkeypatch.setattr("dns.asyncquery.https", fake_https)
    monkeypatch.setattr(
        "dnstrace.transports.doh3.dns.quic.AsyncioQuicManager", _fake_manager_factory("h3")
    )
    transport = DoH3Transport(
        "dns.example",
        url="https://dns.example/dns-query",
        bootstrap_address="192.0.2.53",
    )

    result = await transport.query("example.net", "AAAA")

    assert result.success is True
    assert result.transport == "doh3"
    assert captured["where"] == "https://dns.example/dns-query"
    assert captured["bootstrap_address"] == "192.0.2.53"
    assert captured["http_version"] is dns.query.HTTPVersion.H3
    assert result.protocol == {"alpn": "h3", "tls_version": "TLSv1.3"}
    assert [event.name for event in result.events] == [
        "query.build",
        "http3.request.start",
        "http3.response",
    ]


@pytest.mark.asyncio
async def test_doh3_verifies_hostname_from_url_not_server_ip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manager_kwargs: dict[str, object] = {}

    async def fake_https(message, where, **kwargs):
        return dns.message.make_response(message)

    monkeypatch.setattr("dns.asyncquery.https", fake_https)
    monkeypatch.setattr(
        "dnstrace.transports.doh3.dns.quic.AsyncioQuicManager",
        _fake_manager_factory("h3", captured=manager_kwargs),
    )
    transport = DoH3Transport(
        "10.0.0.53",
        url="https://resolver.example/dns-query",
        bootstrap_address="10.0.0.53",
    )

    result = await transport.query("example.net", "AAAA")

    assert result.success is True
    assert manager_kwargs["server_name"] == "resolver.example"


@pytest.mark.asyncio
async def test_doq_reports_error_on_unexpected_eof(monkeypatch: pytest.MonkeyPatch) -> None:
    async def failing_quic(message, where, **kwargs):
        raise UnexpectedEOF

    monkeypatch.setattr("dns.asyncquery.quic", failing_quic)
    monkeypatch.setattr(
        "dnstrace.transports.doq.dns.quic.AsyncioQuicManager", _fake_manager_factory("doq")
    )
    transport = DoQTransport("192.0.2.53", verify=False)

    result = await transport.query("example.com", "A")

    assert result.success is False
    assert result.error is not None
    assert "UnexpectedEOF" in result.error


@pytest.mark.asyncio
async def test_doh3_reports_error_on_unexpected_eof(monkeypatch: pytest.MonkeyPatch) -> None:
    async def failing_https(message, where, **kwargs):
        raise UnexpectedEOF

    monkeypatch.setattr("dns.asyncquery.https", failing_https)
    monkeypatch.setattr(
        "dnstrace.transports.doh3.dns.quic.AsyncioQuicManager", _fake_manager_factory("h3")
    )
    transport = DoH3Transport(
        "dns.example",
        url="https://dns.example/dns-query",
        bootstrap_address="192.0.2.53",
    )

    result = await transport.query("example.net", "AAAA")

    assert result.success is False
    assert result.error is not None
    assert "UnexpectedEOF" in result.error


def test_engine_builds_quic_transports() -> None:
    engine = TraceEngine(
        server="192.0.2.53",
        doq_port=8853,
        doq_server_hostname="resolver.example",
        doh3_url="https://resolver.example/dns-query",
        doh3_bootstrap_address="192.0.2.53",
        verify_tls=False,
    )

    doq = engine._build_transport("doq")
    doh3 = engine._build_transport("doh3")

    assert isinstance(doq, DoQTransport)
    assert doq.port == 8853
    assert doq.server_hostname == "resolver.example"
    assert doq.verify is False
    assert isinstance(doh3, DoH3Transport)
    assert doh3.url == "https://resolver.example/dns-query"
    assert doh3.bootstrap_address == "192.0.2.53"
    assert doh3.verify is False
