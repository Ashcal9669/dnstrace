# dnstrace

`dnstrace` is an experimental DNS execution tracer for comparing resolver behaviour across UDP, TCP, DoT, DoH, DoQ, and DoH3 using randomized workloads instead of one fixed domain.

## Current milestone

The initial implementation includes:

- randomized, de-duplicated domain workloads
- UDP and TCP DNS queries
- per-query timelines and timing
- concurrent execution
- terminal and JSON output
- a common transport interface ready for DoT, DoH, DoQ, and DoH3

## Install

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

## Run

```bash
dnstrace trace --server 10.0.0.53 --transport udp --transport tcp --random 20
```

JSON output:

```bash
dnstrace trace --server 10.0.0.53 --transport udp --transport tcp --random 20 --json report.json
```

The project is under active development.
