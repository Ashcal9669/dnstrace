from __future__ import annotations

import asyncio
from collections.abc import Iterable

from dnstrace.models import TraceResult
from dnstrace.transports.base import Transport
from dnstrace.transports.tcp import TCPTransport
from dnstrace.transports.udp import UDPTransport


TRANSPORTS: dict[str, type[Transport]] = {
    "udp": UDPTransport,
    "tcp": TCPTransport,
}


class TraceEngine:
    def __init__(self, server: str, timeout: float = 3.0, concurrency: int = 20) -> None:
        self.server = server
        self.timeout = timeout
        self.semaphore = asyncio.Semaphore(concurrency)

    async def _run_one(self, transport: Transport, domain: str, qtype: str) -> TraceResult:
        async with self.semaphore:
            return await transport.query(domain, qtype)

    async def run(
        self,
        domains: Iterable[str],
        qtype: str,
        transport_names: Iterable[str],
    ) -> list[TraceResult]:
        transports: list[Transport] = []
        for name in transport_names:
            try:
                cls = TRANSPORTS[name]
            except KeyError as exc:
                raise ValueError(f"unsupported transport: {name}") from exc
            transports.append(cls(server=self.server, timeout=self.timeout))

        tasks = [
            self._run_one(transport, domain, qtype)
            for domain in domains
            for transport in transports
        ]
        return await asyncio.gather(*tasks)
