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
        typer.Option("--transport", "-t", help="Repeat for udp, tcp, dot, doh, doq, or doh3"),
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
    dot_port: Annotated[int, typer.Option(min=1, max=65535)] = 853,
    dot_server_name: Annotated[
        str | None,
        typer.Option(help="TLS SNI/certificate hostname for DoT; defaults to --server"),
    ] = None,
    doh_url: Annotated[
        str | None,
        typer.Option(help="Complete DoH endpoint, for example https://dns.example/dns-query"),
    ] = None,
    doq_port: Annotated[int, typer.Option(min=1, max=65535)] = 853,
    doq_server_name: Annotated[
        str | None,
        typer.Option(help="QUIC certificate hostname for DoQ; defaults to --server"),
    ] = None,
    doh3_url: Annotated[
        str | None,
        typer.Option(help="Complete DoH3 endpoint, for example https://dns.example/dns-query"),
    ] = None,
    doh3_bootstrap: Annotated[
        str | None,
        typer.Option(help="Bootstrap IP address for the DoH3 endpoint hostname"),
    ] = None,
    insecure: Annotated[
        bool,
        typer.Option("--insecure", help="Disable TLS certificate verification"),
    ] = False,
) -> None:
    """Run a randomized resolver workload over selected transports."""
    workload = build_workload(random_count, domain_file=domain_file, seed=seed)
    engine = TraceEngine(
        server=server,
        timeout=timeout,
        concurrency=concurrency,
        dot_port=dot_port,
        dot_server_hostname=dot_server_name,
        doh_url=doh_url,
        doq_port=doq_port,
        doq_server_hostname=doq_server_name,
        doh3_url=doh3_url,
        doh3_bootstrap_address=doh3_bootstrap,
        verify_tls=not insecure,
    )
    results = asyncio.run(engine.run(workload.domains, qtype.upper(), transport))
    render_terminal(results)
    if json_path is not None:
        write_json(results, json_path)
        typer.echo(f"JSON report written to {json_path}")


if __name__ == "__main__":
    app()
