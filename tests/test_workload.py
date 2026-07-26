from pathlib import Path

import pytest

from dnstrace.workload import DEFAULT_DOMAINS, build_workload


def test_random_workload_is_unique_when_pool_allows() -> None:
    workload = build_workload(5, seed=7)
    assert len(workload.domains) == 5
    assert len(set(workload.domains)) == 5


def test_random_workload_is_repeatable_with_seed() -> None:
    assert build_workload(6, seed=42).domains == build_workload(6, seed=42).domains


def test_domain_file_extends_pool(tmp_path: Path) -> None:
    domain_file = tmp_path / "domains.txt"
    domain_file.write_text("example.net\n# ignored\nexample.org\n", encoding="utf-8")
    workload = build_workload(len(DEFAULT_DOMAINS) + 2, domain_file=domain_file, seed=1)
    assert "example.net" in workload.domains
    assert "example.org" in workload.domains


def test_count_must_be_positive() -> None:
    with pytest.raises(ValueError):
        build_workload(0)
