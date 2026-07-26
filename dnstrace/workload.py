from __future__ import annotations

import random
import re
import secrets
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
    base_domains: list[str]
    fresh: bool = False
    nonce: str | None = None


def _normalize_nonce(value: str) -> str:
    normalized = re.sub(r"[^a-z0-9-]", "-", value.lower()).strip("-")
    if not normalized:
        raise ValueError("fresh nonce must contain at least one letter or number")
    return normalized[:32]


def build_workload(
    count: int,
    domain_file: Path | None = None,
    seed: int | None = None,
    *,
    fresh: bool = False,
    nonce: str | None = None,
) -> Workload:
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
        base_domains = rng.sample(pool, count)
    else:
        base_domains = pool.copy()
        rng.shuffle(base_domains)
        while len(base_domains) < count:
            base_domains.append(rng.choice(pool))

    if not fresh:
        return Workload(domains=base_domains.copy(), base_domains=base_domains)

    fresh_nonce = _normalize_nonce(nonce or secrets.token_hex(6))
    domains = [f"dnstrace-{fresh_nonce}-{index}.{base}" for index, base in enumerate(base_domains)]
    return Workload(
        domains=domains,
        base_domains=base_domains,
        fresh=True,
        nonce=fresh_nonce,
    )
