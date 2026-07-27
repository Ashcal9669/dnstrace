from pathlib import Path

import pytest

from dnstrace.workload import build_independent_workloads, build_workload

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
        f"dnstrace-udp-vs-tcp-{index}.{base}" for index, base in enumerate(workload.base_domains)
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


def test_independent_workloads_share_no_domains() -> None:
    workloads = build_independent_workloads(
        5,
        ["udp", "tcp", "dot"],
        seed=7,
        source_domains=TEST_DOMAINS,
    )
    assert set(workloads) == {"udp", "tcp", "dot"}
    all_domains: list[str] = []
    for workload in workloads.values():
        assert len(workload.domains) == 5
        all_domains.extend(workload.domains)
    assert len(all_domains) == len(set(all_domains))


def test_independent_workloads_are_repeatable_with_seed() -> None:
    first = build_independent_workloads(4, ["udp", "doh"], seed=99, source_domains=TEST_DOMAINS)
    second = build_independent_workloads(4, ["udp", "doh"], seed=99, source_domains=TEST_DOMAINS)
    assert {n: w.domains for n, w in first.items()} == {n: w.domains for n, w in second.items()}


def test_independent_workloads_apply_fresh_labels_per_transport() -> None:
    workloads = build_independent_workloads(
        2,
        ["udp", "doh"],
        seed=1,
        fresh=True,
        nonce="cmp",
        source_domains=TEST_DOMAINS,
    )
    assert workloads["udp"].domains[0].startswith("dnstrace-cmp-udp-0.")
    assert workloads["doh"].domains[0].startswith("dnstrace-cmp-doh-0.")


def test_independent_workloads_require_enough_domains_for_all_transports() -> None:
    with pytest.raises(ValueError, match="source only contains"):
        build_independent_workloads(60, ["udp", "tcp"], source_domains=TEST_DOMAINS)


def test_independent_workloads_require_at_least_one_transport() -> None:
    with pytest.raises(ValueError, match="at least one transport"):
        build_independent_workloads(1, [], source_domains=TEST_DOMAINS)
