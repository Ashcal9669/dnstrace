from __future__ import annotations

import random
import re
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from tranco import Tranco

TRANCO_SAMPLE_SIZE = 1_000_000


@dataclass(slots=True)
class Workload:
    domains: list[str]
    base_domains: list[str]
    fresh: bool = False
    nonce: str | None = None
    source: str = "tranco"


def _normalize_nonce(value: str) -> str:
    normalized = re.sub(r"[^a-z0-9-]", "-", value.lower()).strip("-")
    if not normalized:
        raise ValueError("fresh nonce must contain at least one letter or number")
    return normalized[:32]


def _load_domain_file(path: Path) -> list[str]:
    return [
        line.strip().lower().rstrip(".")
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def _load_tranco_domains(cache_dir: Path | None = None) -> list[str]:
    target = cache_dir or Path.home() / ".cache" / "dnstrace" / "tranco"
    target.mkdir(parents=True, exist_ok=True)
    ranking = Tranco(cache=True, cache_dir=str(target)).list()
    return ranking.top(TRANCO_SAMPLE_SIZE)


def build_workload(
    count: int,
    domain_file: Path | None = None,
    seed: int | None = None,
    *,
    fresh: bool = False,
    nonce: str | None = None,
    source_domains: Iterable[str] | None = None,
) -> Workload:
    if count < 1:
        raise ValueError("count must be at least 1")

    if source_domains is not None:
        pool = list(source_domains)
        source = "provided"
    elif domain_file is not None:
        pool = _load_domain_file(domain_file)
        source = str(domain_file)
    else:
        pool = _load_tranco_domains()
        source = "Tranco latest top 1,000,000"

    pool = sorted({domain.strip().lower().rstrip(".") for domain in pool if domain.strip()})
    if not pool:
        raise ValueError("domain pool is empty")
    if count > len(pool):
        raise ValueError(f"requested {count} domains, but source only contains {len(pool)} unique domains")

    rng = random.Random(seed) if seed is not None else random.SystemRandom()
    base_domains = rng.sample(pool, count)

    if not fresh:
        return Workload(
            domains=base_domains.copy(),
            base_domains=base_domains,
            source=source,
        )

    fresh_nonce = _normalize_nonce(nonce or secrets.token_hex(6))
    domains = [f"dnstrace-{fresh_nonce}-{index}.{base}" for index, base in enumerate(base_domains)]
    return Workload(
        domains=domains,
        base_domains=base_domains,
        fresh=True,
        nonce=fresh_nonce,
        source=source,
    )
