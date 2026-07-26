from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Annotated

import typer

from dnstrace.engine import TraceEngine
from dnstrace.output import render_terminal, write_json
from dnstrace.workload import build_workload


app = typer.Typer(no_args_is_help=True, help="Trace DNS execution across multiple transports.")


@app.command()
def trace(
    server: Annotated[str, typer.Option(help="DNS resolver IP address or hostname")],
    transport: Annotated[
        list[str],
        typer.Option("--transport", "-t", help="Repeat for udp and tcp"),
    ] = ["udp", "tcp"],
    random_count: Annotated[
        int,
        typer.Option("--random", min=1, help="Number of randomized domain queries"),
    ] = 10,
    qtype: Annotated[str, typer.Option(help="DNS record type")] = "A",
    timeout: Annotated[float, typer.Option(min=0.1)] = 3.0,
    concurrency: Annotated[int, typer.Option(min=1)] = 20,
    domain_file: Annotated[Path | None, typer.Option(exists=True, dir_okay=False)] = None,
    seed: Annotated[int | None, typer.Option(help="Repeatable workload seed")] = None,
    json_path: Annotated[Path | None, typer.Option("--json", dir_okay=False)] = None,
) -> None:
    """Run a randomized resolver workload over selected transports."""
    workload = build_workload(random_count, domain_file=domain_file, seed=seed)
    engine = TraceEngine(server=server, timeout=timeout, concurrency=concurrency)
    results = asyncio.run(engine.run(workload.domains, qtype.upper(), transport))
    render_terminal(results)
    if json_path is not None:
        write_json(results, json_path)
        typer.echo(f"JSON report written to {json_path}")


if __name__ == "__main__":
    app()
