# dnstrace

`dnstrace` is an experimental DNS execution tracer for comparing resolver behaviour across UDP, TCP, DoT, DoH, DoQ, and DoH3 using randomized workloads instead of one fixed domain.

## Current milestone

The current implementation includes:

- randomized, de-duplicated domain workloads
- UDP and TCP DNS queries
- DNS-over-TLS with certificate verification, SNI, custom port, and TLS timeline events
- DNS-over-HTTPS using RFC 8484 wire-format requests with HTTP/2 support
- DNS-over-QUIC using RFC 9250 streams
- DNS-over-HTTPS over HTTP/3 with an optional bootstrap address
- per-query timelines and timing
- concurrent execution
- terminal and JSON output
- one transport interface across all six protocols

## Install

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

For development:

```bash
pip install -e '.[dev]'
pytest
```

## Run

UDP and TCP:

```bash
dnstrace trace --server 10.0.0.53 --transport udp --transport tcp --random 20
```

These examples point at a resolver you control (`10.0.0.53`, cert hostname `resolver.example`) — swap in your own resolver's IP and hostname. There's nothing stopping you from pointing `--server` at a public resolver like `1.1.1.1`, but the whole point of dnstrace is comparing transport behaviour against a resolver you actually operate, not benchmarking someone else's edge network.

DNS-over-TLS using a resolver IP with an explicit certificate hostname:

```bash
dnstrace trace \
  --server 10.0.0.53 \
  --transport dot \
  --dot-server-name resolver.example \
  --random 20
```

DNS-over-HTTPS:

```bash
dnstrace trace \
  --server 10.0.0.53 \
  --transport doh \
  --doh-url https://resolver.example/dns-query \
  --random 20
```

DNS-over-QUIC:

```bash
dnstrace trace \
  --server 10.0.0.53 \
  --transport doq \
  --doq-server-name resolver.example \
  --random 20
```

DNS-over-HTTP/3:

```bash
dnstrace trace \
  --server 10.0.0.53 \
  --transport doh3 \
  --doh3-url https://resolver.example/dns-query \
  --doh3-bootstrap 10.0.0.53 \
  --random 20
```

Multiple transports in one workload:

```bash
dnstrace trace \
  --server 10.0.0.53 \
  --transport udp \
  --transport tcp \
  --transport dot \
  --transport doh \
  --transport doq \
  --transport doh3 \
  --dot-server-name resolver.example \
  --doh-url https://resolver.example/dns-query \
  --doq-server-name resolver.example \
  --doh3-url https://resolver.example/dns-query \
  --doh3-bootstrap 10.0.0.53 \
  --random 20 \
  --json report.json
```

`--insecure` disables certificate verification for DoT, DoH, DoQ, and DoH3. Use it only against development resolvers with self-signed certificates.

## Roadmap

- recursive execution tracing
- live TUI
- resolver comparison and anomaly analysis
- connection reuse and session-level timelines

The project is under active development.
