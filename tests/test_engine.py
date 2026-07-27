from __future__ import annotations

import pytest

from dnstrace.engine import TraceEngine
from dnstrace.models import TraceResult
from dnstrace.transports.tcp import TCPTransport
from dnstrace.transports.udp import UDPTransport


@pytest.mark.asyncio
async def test_run_queries_each_transport_with_the_same_domain_by_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: list[tuple[str, str]] = []

    async def fake_query(self, domain: str, qtype: str) -> TraceResult:
        captured.append((self.name, domain))
        return TraceResult(domain=domain, qtype=qtype, transport=self.name, server="192.0.2.53")

    monkeypatch.setattr(UDPTransport, "query", fake_query)
    monkeypatch.setattr(TCPTransport, "query", fake_query)

    engine = TraceEngine("192.0.2.53")
    await engine.run(["example.com"], "A", ["udp", "tcp"])

    assert sorted(captured) == [("tcp", "example.com"), ("udp", "example.com")]


@pytest.mark.asyncio
async def test_run_gives_each_transport_a_distinct_domain_when_fresh(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: list[tuple[str, str]] = []

    async def fake_query(self, domain: str, qtype: str) -> TraceResult:
        captured.append((self.name, domain))
        return TraceResult(domain=domain, qtype=qtype, transport=self.name, server="192.0.2.53")

    monkeypatch.setattr(UDPTransport, "query", fake_query)
    monkeypatch.setattr(TCPTransport, "query", fake_query)

    engine = TraceEngine("192.0.2.53")
    await engine.run(["dnstrace-abc123-0.example.com"], "A", ["udp", "tcp"], fresh=True)

    queried_domains = {domain for _, domain in captured}
    assert queried_domains == {
        "udp.dnstrace-abc123-0.example.com",
        "tcp.dnstrace-abc123-0.example.com",
    }
