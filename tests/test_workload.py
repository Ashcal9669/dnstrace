from pathlib import Path

import pytest

from dnstrace.workload import build_workload

TEST_DOMAINS = [f"site-{index}.example" for index in range(100)]


def test_random_workload_is_unique_when_pool_allows() -> None:
    workload = build_workload(5, seed=7, source_domains=TEST_DOMAINS)
    assert len(workload.domains) == 5
    assert len(set(workload.domains)) == 5
    assert workload.source == "provided"


def test_random_workload_is_repeatable_with_seed() -> None:
    first = build_workload(6, seed=42, source_domains=TEST_DOMAINS).domains
    second = build_workload(6, seed=42, source_domains=TEST_DOMAINS).domains
    assert first == second


def test_random_workload_changes_without_seed() -> None:
    first = build_workload(20, source_domains=TEST_DOMAINS).domains
    second = build_workload(20, source_domains=TEST_DOMAINS).domains
    assert first != second


def test_domain_file_is_the_complete_pool(tmp_path: Path) -> None:
    domain_file = tmp_path / "domains.txt"
    domain_file.write_text("example.net\n# ignored\nexample.org\n", encoding="utf-8")
    workload = build_workload(2, domain_file=domain_file, seed=1)
    assert set(workload.domains) == {"example.net", "example.org"}


def test_fresh_workload_adds_unique_labels() -> None:
    workload = build_workload(
        3,
        seed=42,
        fresh=True,
        nonce="udp-vs-tcp",
        source_domains=TEST_DOMAINS,
    )
    assert workload.fresh is True
    assert workload.nonce == "udp-vs-tcp"
    assert workload.domains == [
        f"dnstrace-udp-vs-tcp-{index}.{base}"
        for index, base in enumerate(workload.base_domains)
    ]


def test_fresh_nonce_is_normalized() -> None:
    workload = build_workload(
        1,
        fresh=True,
        nonce="Test Run #1",
        source_domains=TEST_DOMAINS,
    )
    assert workload.nonce == "test-run--1"


def test_count_must_be_positive() -> None:
    with pytest.raises(ValueError):
        build_workload(0, source_domains=TEST_DOMAINS)


def test_count_cannot_exceed_source() -> None:
    with pytest.raises(ValueError, match="source only contains"):
        build_workload(101, source_domains=TEST_DOMAINS)
