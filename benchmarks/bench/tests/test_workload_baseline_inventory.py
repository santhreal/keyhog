"""Strict baseline artifact inventory contracts."""

from __future__ import annotations

import json
import pathlib

import pytest

from bench.baseline_capture import (
    BASELINE_SCHEMA_VERSION,
    MIN_TRIALS,
    sha256_file,
    workload_measurement_axes,
)
from bench.baseline_inventory import BaselineInventoryError, inventory_baselines
from bench.target_matrix import load_target_matrix, target_matrix_sha256
from bench.workload_catalog import load_workload_catalog

BENCHMARKS = pathlib.Path(__file__).resolve().parents[2]
CATALOG = BENCHMARKS / "workload-catalog.toml"
LOCK = BENCHMARKS / "workload-fixtures.lock.json"
TARGETS = BENCHMARKS / "target-matrix.toml"


def _write_baseline(
    directory: pathlib.Path,
    *,
    backend: str,
    workload_id: str = "slack-workspace-messages",
    binary_sha256: str = "1" * 64,
    suffix: str = "",
) -> pathlib.Path:
    catalog = load_workload_catalog(CATALOG)
    workload = next(row for row in catalog.workloads if row.workload_id == workload_id)
    fixture_lock = json.loads(LOCK.read_text(encoding="utf-8"))
    receipt = next(
        row for row in fixture_lock["workloads"] if row["workload_id"] == workload_id
    )
    target = next(
        row
        for row in load_target_matrix(TARGETS).targets
        if row.target_id == "linux-x86_64-rtx5090"
    )
    trials = [
        {"wall_ms": float(index), "peak_rss_kb": 100 + index}
        for index in range(1, MIN_TRIALS + 1)
    ]
    row = {
        "schema_version": BASELINE_SCHEMA_VERSION,
        "workload_id": workload_id,
        "backend": backend,
        "binary_sha256": binary_sha256,
        "fixture_input_sha256": receipt["input_sha256"],
        "fixture_answer_sha256": receipt["answer_sha256"],
        **workload_measurement_axes(workload),
        "parity_ok": True,
        "p50_wall_ms": 3.0,
        "p95_wall_ms": 5.0,
        "median_peak_rss_kb": 103,
        "max_peak_rss_kb": 105,
        "trials": trials,
    }
    payload = {
        "schema_version": BASELINE_SCHEMA_VERSION,
        "catalog_sha256": fixture_lock["catalog_sha256"],
        "fixture_lock_sha256": sha256_file(LOCK),
        "target_matrix_sha256": target_matrix_sha256(TARGETS),
        "target_id": target.target_id,
        "host_evidence": {
            "os": target.os,
            "arch": target.arch,
            "cpu": target.cpu,
            "logical_cores": target.logical_cores,
            "ram_mb": target.min_ram_mb,
            "gpu": target.gpu,
            "gpu_vram_mb": target.min_gpu_vram_mb,
            "gpu_driver": target.gpu_driver,
            "kernel": "test-kernel",
        },
        "binary_sha256": binary_sha256,
        "backend": backend,
        "repetitions": MIN_TRIALS,
        "workloads": [row],
    }
    path = directory / f"current-v0.5.68-linux-{backend}-{workload_id}{suffix}.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_inventory_reports_exact_missing_set_and_binary_identity(
    tmp_path: pathlib.Path,
) -> None:
    """WHY: partial captures must remain visibly partial; counting artifacts or accepting any nonempty row set would allow a 1-of-59 baseline to masquerade as complete evidence."""
    _write_baseline(tmp_path, backend="cpu")
    _write_baseline(tmp_path, backend="simd")
    inventory = inventory_baselines(
        tmp_path,
        catalog_path=CATALOG,
        fixture_lock_path=LOCK,
        target_matrix_path=TARGETS,
    )
    assert inventory["catalog_workloads"] == 59
    for backend in ("cpu", "simd"):
        row = inventory["backends"][backend]
        assert row["covered"] == ["slack-workspace-messages"]
        assert len(row["missing"]) == 58
        assert "github-organization-repositories" in row["missing"]
        assert len(row["binary_sha256s"]) == 1
    with pytest.raises(BaselineInventoryError, match="generation is incomplete"):
        inventory_baselines(
            tmp_path,
            catalog_path=CATALOG,
            fixture_lock_path=LOCK,
            target_matrix_path=TARGETS,
            require_complete=True,
        )


def test_inventory_rejects_duplicate_workload_evidence(tmp_path: pathlib.Path) -> None:
    """WHY: two timing rows for one workload make p50 provenance ambiguous; the gate must reject duplicates rather than silently choosing by filename order."""
    _write_baseline(tmp_path, backend="cpu", suffix="-a")
    _write_baseline(tmp_path, backend="cpu", suffix="-b")
    with pytest.raises(BaselineInventoryError, match="duplicate cpu workload"):
        inventory_baselines(
            tmp_path,
            catalog_path=CATALOG,
            fixture_lock_path=LOCK,
            target_matrix_path=TARGETS,
            backends=("cpu",),
        )


def test_inventory_rejects_mixed_executable_generation(
    tmp_path: pathlib.Path,
) -> None:
    """WHY: timings from different rebuilt executables cannot describe one current baseline; accepting their union makes regressions irreproducible and comparisons non-causal."""
    _write_baseline(
        tmp_path,
        backend="cpu",
        workload_id="slack-workspace-messages",
        binary_sha256="1" * 64,
    )
    _write_baseline(
        tmp_path,
        backend="cpu",
        workload_id="stdin-tiny",
        binary_sha256="0" * 64,
    )
    with pytest.raises(BaselineInventoryError, match="mixes executable identities"):
        inventory_baselines(
            tmp_path,
            catalog_path=CATALOG,
            fixture_lock_path=LOCK,
            target_matrix_path=TARGETS,
            backends=("cpu",),
        )
