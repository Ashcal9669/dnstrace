from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Annotated

import typer

from dnstrace.engine import TraceEngine
from dnstrace.output import render_terminal, write_json
from dnstrace.workload import build_independent_workloads, build_workload

app = typer.Typer(no_args_is_help=True, help="Trace DNS execution across multiple transports.")


@app.command()
def trace(
    server: Annotated[str, typer.Option(help="DNS resolver IP address or hostname")],
    transport: Annotated[
        list[str] | None,
        typer.Option("--transport", "-t", help="Repeat for udp, tcp, dot, doh, doq, or doh3"),
    ] = None,
    random_count: Annotated[
        int,
        typer.Option("--random", min=1, help="Number of real websites selected at random"),
    ] = 10,
    qtype: Annotated[str, typer.Option(help="DNS record type")] = "A",
    timeout: Annotated[float, typer.Option(min=0.1)] = 3.0,
    concurrency: Annotated[int, typer.Option(min=1)] = 20,
    domain_file: Annotated[
        Path | None,
        typer.Option(
            exists=True,
            dir_okay=False,
            help="Use this domain list instead of the live Tranco website ranking",
        ),
    ] = None,
    seed: Annotated[
        int | None,
        typer.Option(
            help="Repeat the same random website selection; omit for a new sample each run"
        ),
    ] = None,
    fresh: Annotated[
        bool,
        typer.Option(
            "--fresh",
            help=(
                "Give each domain a unique label, and each transport its own copy of that "
                "label, so no transport can serve a cache hit warmed by another transport's query"
            ),
        ),
    ] = False,
    fresh_nonce: Annotated[
        str | None,
        typer.Option(
            help="Reuse the same cache-busting label across separate transport runs for comparison"
        ),
    ] = None,
    independent: Annotated[
        bool,
        typer.Option(
            "--independent",
            help=(
                "Give each transport its own separate batch of random websites, with no "
                "domain shared between transports. Trades away same-site comparison across "
                "protocols in exchange for zero cache or DNSSEC-negative-proof sharing "
                "between them."
            ),
        ),
    ] = False,
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
    doh_get: Annotated[
        bool,
        typer.Option(
            "--doh-get",
            help=(
                "Use HTTP GET instead of POST for DoH and DoH3. Some minimal DoH "
                "servers (for example router-based encrypted DNS proxies) only "
                "support the GET form of RFC 8484 and reject POST with 405/400."
            ),
        ),
    ] = False,
) -> None:
    """Run a randomized resolver workload over selected transports."""
    selected_transports = transport or ["udp", "tcp"]
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
        doh_get=doh_get,
    )

    if independent:
        workloads = build_independent_workloads(
            random_count,
            selected_transports,
            domain_file=domain_file,
            seed=seed,
            fresh=fresh,
            nonce=fresh_nonce,
        )
        typer.echo(f"Website source: {next(iter(workloads.values())).source}")
        for name, workload in workloads.items():
            typer.echo(f"  {name}: " + ", ".join(workload.base_domains))
        typer.echo(
            "No domain is shared between transports; each protocol resolves entirely "
            "independent websites."
        )
        results = asyncio.run(
            engine.run_independent(
                {name: workload.domains for name, workload in workloads.items()},
                qtype.upper(),
            )
        )
    else:
        workload = build_workload(
            random_count,
            domain_file=domain_file,
            seed=seed,
            fresh=fresh,
            nonce=fresh_nonce,
        )
        typer.echo(f"Website source: {workload.source}")
        typer.echo("Selected websites: " + ", ".join(workload.base_domains))
        if workload.fresh:
            typer.echo(
                f"Fresh workload nonce: {workload.nonce} "
                "(each transport queries its own label, so results are not cache hits from "
                "another transport in this run; RA still only proves recursion capability)"
            )
        results = asyncio.run(
            engine.run(workload.domains, qtype.upper(), selected_transports, fresh=workload.fresh)
        )

    render_terminal(results)
    if json_path is not None:
        write_json(results, json_path)
        typer.echo(f"JSON report written to {json_path}")


if __name__ == "__main__":
    app()
