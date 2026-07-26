from __future__ import annotations

import random
from dataclasses import dataclass
from pathlib import Path


DEFAULT_DOMAINS = (
    "apple.com",
    "archive.org",
    "cloudflare.com",
    "debian.org",
    "github.com",
    "ietf.org",
    "kernel.org",
    "mozilla.org",
    "python.org",
    "reddit.com",
    "wikipedia.org",
)


@dataclass(slots=True)
class Workload:
    domains: list[str]


def build_workload(count: int, domain_file: Path | None = None, seed: int | None = None) -> Workload:
    if count < 1:
        raise ValueError("count must be at least 1")

    pool = list(DEFAULT_DOMAINS)
    if domain_file is not None:
        loaded = [
            line.strip().lower().rstrip(".")
            for line in domain_file.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        pool.extend(loaded)

    pool = sorted(set(pool))
    if not pool:
        raise ValueError("domain pool is empty")

    rng = random.Random(seed)
    if count <= len(pool):
        domains = rng.sample(pool, count)
    else:
        domains = pool.copy()
        rng.shuffle(domains)
        while len(domains) < count:
            domains.append(rng.choice(pool))

    return Workload(domains=domains)
