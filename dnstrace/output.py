from __future__ import annotations

import json
from pathlib import Path

from rich.console import Console
from rich.table import Table

from dnstrace.models import TraceResult

console = Console()


def render_terminal(results: list[TraceResult]) -> None:
    table = Table(title="dnstrace")
    table.add_column("Domain")
    table.add_column("Type")
    table.add_column("Transport")
    table.add_column("Result")
    table.add_column("Time")
    table.add_column("Answer / Error")

    for result in results:
        status = result.rcode if result.success else "ERROR"
        elapsed = f"{result.elapsed_ms:.2f} ms" if result.elapsed_ms is not None else "-"
        detail = ", ".join(result.answers) if result.answers else (result.error or "no answer")
        table.add_row(result.domain, result.qtype, result.transport.upper(), status or "-", elapsed, detail)

    console.print(table)


def write_json(results: list[TraceResult], path: Path) -> None:
    path.write_text(
        json.dumps([result.to_dict() for result in results], indent=2, sort_keys=True),
        encoding="utf-8",
    )
