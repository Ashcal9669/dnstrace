from __future__ import annotations

import dns.message
import dns.query
import pytest

from dnstrace.engine import TraceEngine
from dnstrace.transports.doh3 import DoH3Transport
from dnstrace.transports.doq import DoQTransport


@pytest.mark.asyncio
async def test_doq_query_records_quic_timeline(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, object] = {}

    async def fake_quic(message, where, **kwargs):
        captured.update(where=where, **kwargs)
        return dns.message.make_response(message)

    monkeypatch.setattr("dns.asyncquery.quic", fake_quic)
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
    assert captured["verify"] is False
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
    assert [event.name for event in result.events] == [
        "query.build",
        "http3.request.start",
        "http3.response",
    ]


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
