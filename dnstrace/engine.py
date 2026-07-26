from __future__ import annotations

import asyncio
from collections.abc import Iterable

from dnstrace.models import TraceResult
from dnstrace.transports.base import Transport
from dnstrace.transports.doh import DoHTransport
from dnstrace.transports.dot import DoTTransport
from dnstrace.transports.tcp import TCPTransport
from dnstrace.transports.udp import UDPTransport


TRANSPORTS: dict[str, type[Transport]] = {
    "udp": UDPTransport,
    "tcp": TCPTransport,
    "dot": DoTTransport,
    "doh": DoHTransport,
}


class TraceEngine:
    def __init__(
        self,
        server: str,
        timeout: float = 3.0,
        concurrency: int = 20,
        *,
        dot_port: int = 853,
        dot_server_hostname: str | None = None,
        doh_url: str | None = None,
        verify_tls: bool = True,
    ) -> None:
        self.server = server
        self.timeout = timeout
        self.semaphore = asyncio.Semaphore(concurrency)
        self.dot_port = dot_port
        self.dot_server_hostname = dot_server_hostname
        self.doh_url = doh_url
        self.verify_tls = verify_tls

    def _build_transport(self, name: str) -> Transport:
        if name == "dot":
            return DoTTransport(
                server=self.server,
                port=self.dot_port,
                timeout=self.timeout,
                server_hostname=self.dot_server_hostname,
                verify=self.verify_tls,
            )
        if name == "doh":
            return DoHTransport(
                server=self.server,
                timeout=self.timeout,
                url=self.doh_url,
                verify=self.verify_tls,
            )
        try:
            cls = TRANSPORTS[name]
        except KeyError as exc:
            supported = ", ".join(sorted(TRANSPORTS))
            raise ValueError(f"unsupported transport: {name}; choose from {supported}") from exc
        return cls(server=self.server, timeout=self.timeout)

    async def _run_one(self, transport: Transport, domain: str, qtype: str) -> TraceResult:
        async with self.semaphore:
            return await transport.query(domain, qtype)

    async def run(
        self,
        domains: Iterable[str],
        qtype: str,
        transport_names: Iterable[str],
    ) -> list[TraceResult]:
        transports = [self._build_transport(name.lower()) for name in transport_names]
        tasks = [
            self._run_one(transport, domain, qtype)
            for domain in domains
            for transport in transports
        ]
        return await asyncio.gather(*tasks)
