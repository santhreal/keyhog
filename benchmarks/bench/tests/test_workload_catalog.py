"""Behavioral contracts for the complete performance workload inventory."""

from __future__ import annotations

import pathlib

import pytest

from bench.workload_catalog import (
    CPU_SIMD_MAX_RSS_BYTES,
    REQUIRED_FAMILIES,
    WorkloadCatalogError,
    load_workload_catalog,
    validate_owner_paths,
)

CATALOG = pathlib.Path(__file__).resolve().parents[2] / "workload-catalog.toml"


def _catalog_text() -> str:
    return CATALOG.read_text(encoding="utf-8")


def _load_text(tmp_path: pathlib.Path, text: str):
    path = tmp_path / "workload-catalog.toml"
    path.write_text(text, encoding="utf-8")
    return load_workload_catalog(path)


def test_canonical_catalog_covers_every_operator_family_and_hard_target() -> None:
    """WHY: an omitted source family or weakened goal would let a fast subset masquerade as an end-to-end performance release."""
    catalog = load_workload_catalog(CATALOG)
    validate_owner_paths(catalog, CATALOG.parents[1])
    assert {workload.family for workload in catalog.workloads} == REQUIRED_FAMILIES
    assert len(catalog.workloads) == 59
    assert catalog.targets.min_speedup == 2.0
    assert catalog.targets.max_rss_ratio == 0.25
    assert catalog.targets.cpu_simd_max_rss_bytes == CPU_SIMD_MAX_RSS_BYTES
    assert catalog.targets.betterleaks_max_time_ratio == 0.25
    assert catalog.targets.gpu_min_speedup == 10.0
    assert sum(workload.betterleaks_comparable for workload in catalog.workloads) == 18
    assert sum(workload.gpu_eligible for workload in catalog.workloads) == 36
    assert all(workload.fixture for workload in catalog.workloads)


@pytest.mark.parametrize(
    ("old", "new", "message"),
    [
        ("min_speedup = 2.0", "min_speedup = 1.99", "min_speedup"),
        ("max_rss_ratio = 0.25", "max_rss_ratio = 0.251", "max_rss_ratio"),
        (
            "cpu_simd_max_rss_bytes = 134217728",
            "cpu_simd_max_rss_bytes = 134217729",
            "cpu_simd_max_rss_bytes",
        ),
        (
            "betterleaks_max_time_ratio = 0.25",
            "betterleaks_max_time_ratio = 0.251",
            "betterleaks_max_time_ratio",
        ),
        ("gpu_min_speedup = 10.0", "gpu_min_speedup = 9.99", "gpu_min_speedup"),
    ],
)
def test_catalog_rejects_any_weakened_release_target(
    tmp_path: pathlib.Path, old: str, new: str, message: str
) -> None:
    """WHY: the performance program failed by moving local goals; every hard floor must fail closed when reduced by even one unit."""
    weakened = _catalog_text().replace(old, new, 1)
    with pytest.raises(WorkloadCatalogError, match=message):
        _load_text(tmp_path, weakened)


def test_catalog_rejects_a_missing_workload_family(tmp_path: pathlib.Path) -> None:
    """WHY: deleting the only Slack workload must not silently redefine complete coverage around easier local sources."""
    text = _catalog_text()
    start = text.index('[[workload]]\nid = "slack-workspace-messages"')
    end = text.index("[[workload]]", start + len("[[workload]]"))
    without_slack = text[:start] + text[end:]
    with pytest.raises(WorkloadCatalogError, match="omits required families.*slack"):
        _load_text(tmp_path, without_slack)


def test_catalog_rejects_duplicate_workload_identity(tmp_path: pathlib.Path) -> None:
    """WHY: duplicate IDs merge unrelated result rows and can hide the slower or larger workload behind the same reporting key."""
    duplicate = _catalog_text().replace(
        'id = "stdin-tiny"', 'id = "stdin-empty"', 1
    )
    with pytest.raises(WorkloadCatalogError, match="duplicate id 'stdin-empty'"):
        _load_text(tmp_path, duplicate)


def test_catalog_rejects_an_incomplete_measurement_axis(tmp_path: pathlib.Path) -> None:
    """WHY: removing a backend or policy axis would leave a supported runtime route entirely outside the performance gates."""
    incomplete = _catalog_text().replace(
        'backends = ["auto", "cpu", "simd", "gpu-cuda", "gpu-wgpu", "gpu-metal"]',
        'backends = ["auto", "cpu", "simd", "gpu-cuda", "gpu-wgpu"]',
        1,
    )
    with pytest.raises(WorkloadCatalogError, match="dimensions.backends.*gpu-metal"):
        _load_text(tmp_path, incomplete)


def test_catalog_rejects_untraceable_owner_paths(tmp_path: pathlib.Path) -> None:
    """WHY: every performance row must trace to live implementation or fixture ownership rather than a dead historical path."""
    broken = _catalog_text().replace(
        "benchmarks/workload_matrix/generate.py:build_empty_dir",
        "benchmarks/workload_matrix/missing.py:build_empty_dir",
        1,
    )
    catalog = _load_text(tmp_path, broken)
    with pytest.raises(WorkloadCatalogError, match="owner paths do not exist.*filesystem-empty-directory"):
        validate_owner_paths(catalog, CATALOG.parents[1])


def test_catalog_rejects_owner_path_escape(tmp_path: pathlib.Path) -> None:
    """WHY: repository-relative ownership keeps benchmark evidence bound to reviewed project artifacts and blocks ambient-file substitution."""
    escaped = _catalog_text().replace(
        "benchmarks/workload_matrix/generate.py:build_empty_dir",
        "../outside.py:build_empty_dir",
        1,
    )
    catalog = _load_text(tmp_path, escaped)
    with pytest.raises(WorkloadCatalogError, match="owner paths must be repository-relative"):
        validate_owner_paths(catalog, CATALOG.parents[1])


def test_catalog_rejects_missing_canonical_fixture_path(tmp_path: pathlib.Path) -> None:
    """WHY: a workload name without an executable fixture cannot produce baseline, parity, or regression evidence and must block the contract."""
    broken = _catalog_text().replace(
        'fixture = "benchmarks/bench/workload_fixtures.py:filesystem-empty-directory"',
        'fixture = "benchmarks/bench/missing-fixture.py"',
        1,
    )
    catalog = _load_text(tmp_path, broken)
    with pytest.raises(WorkloadCatalogError, match="owner paths do not exist.*filesystem-empty-directory.fixture"):
        validate_owner_paths(catalog, CATALOG.parents[1])
