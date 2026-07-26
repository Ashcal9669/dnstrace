from __future__ import annotations

from abc import ABC, abstractmethod

from dnstrace.models import TraceResult


class Transport(ABC):
    name: str

    def __init__(self, server: str, port: int = 53, timeout: float = 3.0) -> None:
        self.server = server
        self.port = port
        self.timeout = timeout

    @abstractmethod
    async def query(self, domain: str, qtype: str) -> TraceResult:
        raise NotImplementedError
