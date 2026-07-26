# dnstrace

`dnstrace` is an experimental DNS execution tracer for comparing resolver behaviour across UDP, TCP, DoT, DoH, DoQ, and DoH3 using randomized workloads instead of one fixed domain.

## Current milestone

The current implementation includes:

- randomized, de-duplicated domain workloads
- UDP and TCP DNS queries
- DNS-over-TLS with certificate verification, SNI, custom port, and TLS timeline events
- DNS-over-HTTPS using RFC 8484 wire-format requests with HTTP/2 support
- per-query timelines and timing
- concurrent execution
- terminal and JSON output
- a common transport interface ready for DoQ and DoH3

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

DNS-over-TLS using a resolver IP with an explicit certificate hostname:

```bash
dnstrace trace \
  --server 1.1.1.1 \
  --transport dot \
  --dot-server-name cloudflare-dns.com \
  --random 20
```

DNS-over-HTTPS:

```bash
dnstrace trace \
  --server 1.1.1.1 \
  --transport doh \
  --doh-url https://cloudflare-dns.com/dns-query \
  --random 20
```

Multiple transports in one workload:

```bash
dnstrace trace \
  --server 1.1.1.1 \
  --transport udp \
  --transport tcp \
  --transport dot \
  --transport doh \
  --dot-server-name cloudflare-dns.com \
  --doh-url https://cloudflare-dns.com/dns-query \
  --random 20 \
  --json report.json
```

`--insecure` disables TLS certificate verification and should only be used against development resolvers with self-signed certificates.

## Roadmap

- DoQ
- DoH3
- recursive execution tracing
- live TUI
- resolver comparison and anomaly analysis

The project is under active development.
