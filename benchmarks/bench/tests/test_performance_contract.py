"""Per-workload performance release contracts."""

from __future__ import annotations

import copy
import pathlib

import pytest

from bench.performance_contract import PerformanceContractError, evaluate_betterleaks_memory_contract, evaluate_exhaustive_performance_gate, evaluate_performance_contract
from bench.workload_catalog import load_workload_catalog
CATALOG = load_workload_catalog(pathlib.Path(__file__).resolve().parents[2] / "workload-catalog.toml")


def _row(workload_id: str, *, wall: float, rss: int, parity: bool = True) -> dict[str, object]:
    """Test helper / contract verification."""
    return {
        "workload_id": workload_id,
        "fixture_input_sha256": "a" * 64,
        "fixture_answer_sha256": "b" * 64,
        "p50_wall_ms": wall,
        "max_peak_rss_kb": rss,
        "parity_ok": parity,
        "policy": "default",
        "process_state": "cold",
        "page_cache_state": "uncontrolled",
        "output_format": "json-envelope",
        "execution_route": "in-process",
        "trials": [{"wall_ms": wall, "peak_rss_kb": rss} for _ in range(5)],
    }


def _evidence(*, backend: str = "cpu", speedup: float = 2.0, rss_ratio: float = 0.25):
    """Test helper / contract verification."""
    baseline_rows = []
    candidate_rows = []
    for workload in CATALOG.workloads:
        for route in workload.execution_routes:
            b_row = _row(workload.workload_id, wall=100.0, rss=400_000)
            b_row["execution_route"] = route
            c_row = _row(workload.workload_id, wall=100.0 / speedup, rss=round(400_000 * rss_ratio))
            c_row["execution_route"] = route
            if backend.startswith("gpu-") and workload.gpu_eligible:
                b_row["max_peak_vram_bytes"] = 4_000_000_000
                c_row["max_peak_vram_bytes"] = 1_000_000_000
            baseline_rows.append(b_row)
            candidate_rows.append(c_row)
    baseline = {"backend": backend, "workloads": baseline_rows}
    candidate = {"backend": backend, "workloads": candidate_rows}
    return baseline, candidate

def test_every_workload_meeting_exact_floors_passes() -> None:
    """WHY: the gate must accept equality at the stated 2x, quarter-memory, and 128 MiB boundaries rather than silently demanding an undocumented margin."""
    baseline, candidate = _evidence()
    assert evaluate_performance_contract(baseline, candidate, CATALOG) == []


def test_one_slow_workload_fails_even_when_all_others_are_fast() -> None:
    """WHY: averaging across the catalog would let fast tiny scans hide a regression on one supported operator workload."""
    baseline, candidate = _evidence(speedup=3.0)
    candidate["workloads"][17]["p50_wall_ms"] = 51.0
    violations = evaluate_performance_contract(baseline, candidate, CATALOG)
    assert violations == [f"{candidate['workloads'][17]['workload_id']}: speedup 1.960784x is below 2.000000x"]


def test_missing_route_is_invalid_evidence_not_a_pass() -> None:
    """WHY: a candidate could otherwise omit its slowest route while retaining another row for the same workload and satisfy every computed ratio."""
    baseline, candidate = _evidence()
    missing_row = candidate["workloads"].pop()
    missing = (missing_row["workload_id"], missing_row["execution_route"])
    with pytest.raises(PerformanceContractError) as error:
        evaluate_performance_contract(baseline, candidate, CATALOG)
    assert f"missing=[{missing!r}]" in str(error.value)


def test_single_trial_evidence_is_rejected() -> None:
    """WHY: one favorable scheduler sample cannot establish a p50 or p95 and must never satisfy a release floor."""
    baseline, candidate = _evidence()
    candidate["workloads"][0]["trials"] = candidate["workloads"][0]["trials"][:1]
    with pytest.raises(PerformanceContractError, match="fewer than 5 trials"):
        evaluate_performance_contract(baseline, candidate, CATALOG)


def test_peak_ratio_uses_maximum_not_median_rss() -> None:
    """WHY: the objective caps peak memory for every workload; a low median must not conceal one high-water allocation spike."""
    baseline, candidate = _evidence(rss_ratio=0.25)
    candidate["workloads"][0]["max_peak_rss_kb"] = 100_001
    violations = evaluate_performance_contract(baseline, candidate, CATALOG)
    assert any("peak RSS ratio 0.250003 exceeds 0.250000" in item for item in violations)


def test_cpu_ceiling_is_independent_of_quarter_ratio() -> None:
    """WHY: a memory-heavy baseline can make one quarter exceed 128 MiB; CPU and SIMD must satisfy both constraints independently."""
    baseline, candidate = _evidence(rss_ratio=0.25)
    for row in baseline["workloads"]:
        row["max_peak_rss_kb"] = 800_000
    for row in candidate["workloads"]:
        row["max_peak_rss_kb"] = 200_000
    violations = evaluate_performance_contract(baseline, candidate, CATALOG)
    assert any("CPU/SIMD ceiling" in item for item in violations)


def test_betterleaks_ceiling_requires_parity_and_quarter_time() -> None:
    """WHY: a faster result is not comparable when either scanner misses the canonical finding, and every shared workload must finish within one quarter of Betterleaks time."""
    baseline, candidate = _evidence(speedup=4.0)
    better = {
        "backend": "betterleaks",
        "workloads": [
            _row(workload.workload_id, wall=100.0, rss=100_001)
            for workload in CATALOG.workloads if workload.betterleaks_comparable
        ],
    }
    assert evaluate_performance_contract(baseline, candidate, CATALOG, betterleaks=better) == []
    better["workloads"][0]["parity_ok"] = False
    candidate["workloads"][next(i for i,row in enumerate(candidate["workloads"]) if row["workload_id"] == better["workloads"][1]["workload_id"])]["p50_wall_ms"] = 25.01
    violations = evaluate_performance_contract(baseline, candidate, CATALOG, betterleaks=better)
    assert any("Betterleaks finding parity is not proven" in item for item in violations)
    assert any("Betterleaks time ratio 0.250100 exceeds 0.250000" in item for item in violations)


def test_gpu_contract_requires_tenfold_improvement_per_workload() -> None:
    """WHY: a 10x aggregate GPU headline cannot hide one route that still transfers or computes outside VYRE and reaches only 9.9x."""
    baseline, candidate = _evidence(backend="gpu-cuda", speedup=10.0)
    assert evaluate_performance_contract(baseline, candidate, CATALOG) == []
    candidate["workloads"][5]["p50_wall_ms"] = 10.01
    assert any("below 10.000000x" in item for item in evaluate_performance_contract(baseline, candidate, CATALOG))


def test_candidate_parity_failure_is_release_blocking() -> None:
    """WHY: skipping bytes can create arbitrarily fast scans; performance evidence counts only when exact finding parity is preserved."""
    baseline, candidate = _evidence()
    candidate["workloads"][3]["parity_ok"] = False
    violations = evaluate_performance_contract(baseline, candidate, CATALOG)
    assert f"{candidate['workloads'][3]['workload_id']}: candidate finding parity is not proven" in violations


def test_cold_warm_and_steady_evidence_cannot_be_blended() -> None:
    """WHY: a warm daemon candidate cannot be compared to cold-process baseline startup and called a speedup; process and cache states are separate contracts."""
    baseline,candidate=_evidence()
    candidate["workloads"][0]["process_state"]="warm"
    with pytest.raises(PerformanceContractError,match="candidate process_state differs"):
        evaluate_performance_contract(baseline,candidate,CATALOG)


def test_gpu_host_rss_and_device_vram_are_independent_ceilings() -> None:
    """WHY: low host RSS cannot offset excess device allocations, and low VRAM cannot offset excess host materialization; both memory domains need their own high-water ratio."""
    baseline,candidate=_evidence(backend="gpu-cuda",speedup=10.0)
    gpu_w = next(w for w in CATALOG.workloads if w.gpu_eligible)
    c_row = next(r for r in candidate["workloads"] if r["workload_id"] == gpu_w.workload_id)
    c_row["max_peak_vram_bytes"] = 1_000_000_001
    violations = evaluate_performance_contract(baseline, candidate, CATALOG)
    assert any("device VRAM ratio" in item for item in violations)
    c_row["max_peak_vram_bytes"] = 1_000_000_000
    c_row["max_peak_rss_kb"] = 100_001
    assert any("peak RSS ratio" in item for item in evaluate_performance_contract(baseline, candidate, CATALOG))

def test_betterleaks_memory_requires_strictly_lower_peak_for_every_shared_workload() -> None:
    """WHY: equality or one high-memory shared route disproves the release claim even when all timing and existing baseline-memory ceilings pass."""
    baseline, candidate = _evidence(speedup=4.0)
    better = {
        "backend": "betterleaks",
        "workloads": [
            _row(workload.workload_id, wall=100.0, rss=100_001)
            for workload in CATALOG.workloads if workload.betterleaks_comparable
        ],
    }
    first = better["workloads"][0]
    candidate_row = next(
        row for row in candidate["workloads"]
        if row["workload_id"] == first["workload_id"]
    )
    candidate_row["max_peak_rss_kb"] = 100_001
    violations = evaluate_performance_contract(
        baseline, candidate, CATALOG, betterleaks=better
    )
    assert (
        f"{first['workload_id']}: candidate peak RSS 100001 KiB is not "
        "strictly below Betterleaks 100001 KiB"
    ) in violations
    candidate_row["max_peak_rss_kb"] = 100_000
    assert evaluate_performance_contract(
        baseline, candidate, CATALOG, betterleaks=better
    ) == []


def test_betterleaks_comparison_rejects_coverage_and_fixture_provenance_gaps() -> None:
    """WHY: a lower RSS from a different fixture or a competitor artifact missing the hardest shared workload is not evidence for the catalog-wide claim."""
    baseline, candidate = _evidence(speedup=4.0)
    better = {
        "backend": "betterleaks",
        "workloads": [
            _row(workload.workload_id, wall=100.0, rss=100_001)
            for workload in CATALOG.workloads if workload.betterleaks_comparable
        ],
    }
    missing = better["workloads"].pop()["workload_id"]
    with pytest.raises(PerformanceContractError, match=rf"missing=\['{missing}'\]"):
        evaluate_performance_contract(
            baseline, candidate, CATALOG, betterleaks=better
        )
    better = {
        "backend": "betterleaks",
        "workloads": [
            _row(workload.workload_id, wall=100.0, rss=100_001)
            for workload in CATALOG.workloads if workload.betterleaks_comparable
        ],
    }
    better["workloads"][0]["fixture_input_sha256"] = "c" * 64
    with pytest.raises(PerformanceContractError, match="fixture identity differs"):
        evaluate_performance_contract(
            baseline, candidate, CATALOG, betterleaks=better
        )

def test_standalone_betterleaks_memory_gate_requires_exact_shared_provenance() -> None:
    """WHY: shared-only candidate captures need a strict gate without pretending to satisfy the separate 59-workload end-to-end speed contract."""
    _baseline, full_candidate = _evidence(speedup=4.0)
    shared = {
        workload.workload_id
        for workload in CATALOG.workloads if workload.betterleaks_comparable
    }
    provenance = {
        "catalog_sha256": "c" * 64,
        "fixture_lock_sha256": "f" * 64,
        "target_matrix_sha256": "t" * 64,
        "target_id": "linux-x86_64-rtx5090",
        "host_evidence": {"cpu": "exact"},
    }
    candidate = {
        "backend": "cpu",
        "workloads": [
            copy.deepcopy(row)
            for row in full_candidate["workloads"]
            if row["workload_id"] in shared
        ],
        **provenance,
    }
    better = {
        "backend": "betterleaks",
        "workloads": [
            _row(workload_id, wall=100.0, rss=100_001)
            for workload_id in sorted(shared)
        ],
        **provenance,
    }
    assert evaluate_betterleaks_memory_contract(candidate, better, CATALOG) == []
    first = sorted(shared)[0]
    candidate_row = next(
        row for row in candidate["workloads"] if row["workload_id"] == first
    )
    candidate_row["max_peak_rss_kb"] = 100_001
    violations = evaluate_betterleaks_memory_contract(candidate, better, CATALOG)
    assert any(
        item == (
            f"{first}: candidate peak RSS 100001 KiB is not strictly below "
            "Betterleaks 100001 KiB"
        )
        for item in violations
    )
    candidate_row["max_peak_rss_kb"] = 100_000
    better["target_id"] = "different-host"
    with pytest.raises(PerformanceContractError, match="target_id provenance differs"):
        evaluate_betterleaks_memory_contract(candidate, better, CATALOG)
def test_evaluate_exhaustive_performance_gate_enforces_all_backends() -> None:
    """WHY: KH-2007 requires a single gate to enumerate the catalog and fail on any backend/workload violation."""
    cpu_base, cpu_cand = _evidence(backend="cpu", speedup=2.0)
    simd_base, simd_cand = _evidence(backend="simd", speedup=2.0)
    gpu_base, gpu_cand = _evidence(backend="gpu-cuda", speedup=10.0)

    runs = {
        "cpu": (cpu_base, cpu_cand),
        "simd": (simd_base, simd_cand),
        "gpu-cuda": (gpu_base, gpu_cand),
    }

    violations = evaluate_exhaustive_performance_gate(runs, CATALOG)
    assert violations == []

    # Inject a violation in simd
    simd_cand["workloads"][0]["parity_ok"] = False
    violations = evaluate_exhaustive_performance_gate(runs, CATALOG)
    assert len(violations) >= 1
    assert any("[simd]" in v for v in violations)
def test_evaluate_exhaustive_performance_gate_rejects_invalid_inputs() -> None:
    """WHY: non-mapping or invalid pair structures in runs_by_backend fail closed with PerformanceContractError."""
    with pytest.raises(PerformanceContractError, match="at least one backend"):
        evaluate_exhaustive_performance_gate({}, CATALOG)
    with pytest.raises(PerformanceContractError, match=r"must be a \(baseline, candidate\) pair"):
        evaluate_exhaustive_performance_gate({"cpu": (1, 2, 3)}, CATALOG, required_backends={"cpu"}) # type: ignore
    with pytest.raises(PerformanceContractError, match="baseline and candidate must be mappings"):
        evaluate_exhaustive_performance_gate({"cpu": ("invalid", "invalid")}, CATALOG, required_backends={"cpu"}) # type: ignore
