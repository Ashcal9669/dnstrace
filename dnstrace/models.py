from __future__ import annotations

from dataclasses import asdict, dataclass, field
from time import perf_counter
from typing import Any


@dataclass(slots=True)
class TraceEvent:
    offset_ms: float
    name: str
    detail: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class TraceResult:
    domain: str
    qtype: str
    transport: str
    server: str
    success: bool = False
    elapsed_ms: float | None = None
    rcode: str | None = None
    flags: list[str] = field(default_factory=list)
    answers: list[str] = field(default_factory=list)
    error: str | None = None
    protocol: dict[str, Any] = field(default_factory=dict)
    events: list[TraceEvent] = field(default_factory=list)
    _started: float = field(default_factory=perf_counter, repr=False)

    def event(self, name: str, **detail: Any) -> None:
        self.events.append(
            TraceEvent(offset_ms=(perf_counter() - self._started) * 1000, name=name, detail=detail)
        )

    def evidence(self, **details: Any) -> None:
        self.protocol.update(details)

    def finish(self) -> None:
        self.elapsed_ms = (perf_counter() - self._started) * 1000

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data.pop("_started", None)
        return data
