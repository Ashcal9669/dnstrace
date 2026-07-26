import dns.message
import pytest

from dnstrace.engine import TraceEngine
from dnstrace.transports.doh import DoHTransport
from dnstrace.transports.dot import DoTTransport


@pytest.mark.asyncio
async def test_dot_transport_records_tls_timeline(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_tls(query, where, **kwargs):
        assert where == "1.1.1.1"
        assert kwargs["port"] == 853
        assert kwargs["server_hostname"] == "cloudflare-dns.com"
        return dns.message.make_response(query)

    monkeypatch.setattr("dnstrace.transports.dot.dns.asyncquery.tls", fake_tls)
    transport = DoTTransport(
        "1.1.1.1",
        server_hostname="cloudflare-dns.com",
        verify=False,
    )

    result = await transport.query("example.com", "A")

    assert result.success is True
    assert result.rcode == "NOERROR"
    assert [event.name for event in result.events] == [
        "query.build",
        "tcp.connect",
        "tls.handshake.start",
        "tls.handshake.complete",
        "dns.receive",
    ]


@pytest.mark.asyncio
async def test_doh_transport_uses_configured_endpoint(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_https(query, where, **kwargs):
        assert where == "https://dns.example/dns-query"
        assert kwargs["verify"] is True
        assert kwargs["post"] is True
        return dns.message.make_response(query)

    monkeypatch.setattr("dnstrace.transports.doh.dns.asyncquery.https", fake_https)
    transport = DoHTransport("192.0.2.53", url="https://dns.example/dns-query")

    result = await transport.query("example.net", "AAAA")

    assert result.success is True
    assert result.rcode == "NOERROR"
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
