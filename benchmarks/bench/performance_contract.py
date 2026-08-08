"""Fail-closed per-workload speed, memory, parity, and competitor contracts."""

from __future__ import annotations

from collections.abc import Mapping

from .baseline_capture import MIN_TRIALS
from .workload_catalog import WorkloadCatalog


class PerformanceContractError(RuntimeError):
    """Performance evidence is incomplete, stale, or incomparable."""


def _rows(payload: Mapping[str, object], label: str) -> dict[str, Mapping[str, object]]:
    """Extract and validate workload rows from baseline or candidate payload."""
    raw = payload.get("workloads")
    if not isinstance(raw, list):
        raise PerformanceContractError(f"{label} workloads must be an array")
    rows: dict[str, Mapping[str, object]] = {}
    for index, row in enumerate(raw):
        if not isinstance(row, Mapping) or not isinstance(row.get("workload_id"), str):
            raise PerformanceContractError(f"{label} workload[{index}] is malformed")
        workload_id = str(row["workload_id"])
        if workload_id in rows:
            raise PerformanceContractError(f"{label} duplicates workload {workload_id!r}")
        trials = row.get("trials")
        if not isinstance(trials, list) or len(trials) < MIN_TRIALS:
            raise PerformanceContractError(
                f"{label} workload {workload_id!r} has fewer than {MIN_TRIALS} trials"
            )
        rows[workload_id] = row
    return rows


def _positive(row: Mapping[str, object], field: str, label: str) -> float:
    """Extract a positive numeric metric field from a workload row."""
    value = row.get(field)
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
        raise PerformanceContractError(f"{label} {field} must be positive, got {value!r}")
    return float(value)
def evaluate_betterleaks_memory_contract(
    candidate: Mapping[str, object],
    betterleaks: Mapping[str, object],
    catalog: WorkloadCatalog,
) -> list[str]:
    """Require every shared CPU/SIMD workload to use strictly less peak RSS."""
    backend = candidate.get("backend")
    if backend not in {"cpu", "simd"}:
        raise PerformanceContractError(
            "Betterleaks memory evidence requires a CPU or SIMD candidate"
        )
    candidate_rows = _rows(candidate, "candidate")
    competitor_rows = _rows(betterleaks, "betterleaks")
    shared = {
        workload.workload_id
        for workload in catalog.workloads
        if workload.betterleaks_comparable
    }
    for label, rows in (("candidate", candidate_rows), ("Betterleaks", competitor_rows)):
        if set(rows) != shared:
            raise PerformanceContractError(
                f"{label} shared coverage differs: missing={sorted(shared-set(rows))}, "
                f"extra={sorted(set(rows)-shared)}"
            )
    provenance_fields = (
        "catalog_sha256", "fixture_lock_sha256", "target_matrix_sha256",
        "target_id", "host_evidence",
    )
    for field in provenance_fields:
        if candidate.get(field) != betterleaks.get(field):
            raise PerformanceContractError(
                f"candidate and Betterleaks {field} provenance differs"
            )
    violations: list[str] = []
    for workload_id in sorted(shared):
        after = candidate_rows[workload_id]
        competitor = competitor_rows[workload_id]
        if (
            competitor.get("fixture_input_sha256") != after.get("fixture_input_sha256")
            or competitor.get("fixture_answer_sha256") != after.get("fixture_answer_sha256")
        ):
            raise PerformanceContractError(
                f"{workload_id}: Betterleaks and candidate fixture identity differs"
            )
        if after.get("parity_ok") is not True:
            violations.append(f"{workload_id}: candidate finding parity is not proven")
        if competitor.get("parity_ok") is not True:
            violations.append(f"{workload_id}: Betterleaks finding parity is not proven")
        candidate_rss = _positive(
            after, "max_peak_rss_kb", f"candidate {workload_id}"
        )
        competitor_rss = _positive(
            competitor, "max_peak_rss_kb", f"Betterleaks {workload_id}"
        )
        if candidate_rss >= competitor_rss:
            violations.append(
                f"{workload_id}: candidate peak RSS {int(candidate_rss)} KiB is not "
                f"strictly below Betterleaks {int(competitor_rss)} KiB"
            )
    return violations


def evaluate_performance_contract(
    baseline: Mapping[str, object],
    candidate: Mapping[str, object],
    catalog: WorkloadCatalog,
    *,
    betterleaks: Mapping[str, object] | None = None,
) -> list[str]:
    """Return every release violation; malformed or missing evidence raises."""
    baseline_rows = _rows(baseline, "baseline")
    candidate_rows = _rows(candidate, "candidate")
    expected = {workload.workload_id for workload in catalog.workloads}
    if set(baseline_rows) != expected:
        raise PerformanceContractError(
            f"baseline coverage differs: missing={sorted(expected-set(baseline_rows))}, "
            f"extra={sorted(set(baseline_rows)-expected)}"
        )
    if set(candidate_rows) != expected:
        raise PerformanceContractError(
            f"candidate coverage differs: missing={sorted(expected-set(candidate_rows))}, "
            f"extra={sorted(set(candidate_rows)-expected)}"
        )
    backend = candidate.get("backend")
    if not isinstance(backend, str):
        raise PerformanceContractError("candidate backend is missing")
    gpu = backend.startswith("gpu-")
    speed_floor = catalog.targets.gpu_min_speedup if gpu else catalog.targets.min_speedup
    competitor_rows = _rows(betterleaks, "betterleaks") if betterleaks is not None else {}
    if betterleaks is not None:
        shared = {
            workload.workload_id
            for workload in catalog.workloads
            if workload.betterleaks_comparable
        }
        if set(competitor_rows) != shared:
            raise PerformanceContractError(
                "Betterleaks coverage differs: "
                f"missing={sorted(shared-set(competitor_rows))}, "
                f"extra={sorted(set(competitor_rows)-shared)}"
            )
    violations: list[str] = []
    for workload in catalog.workloads:
        workload_id = workload.workload_id
        before = baseline_rows[workload_id]
        after = candidate_rows[workload_id]
        if (
            before.get("fixture_input_sha256") != after.get("fixture_input_sha256")
            or before.get("fixture_answer_sha256") != after.get("fixture_answer_sha256")
        ):
            raise PerformanceContractError(f"{workload_id}: baseline and candidate fixture identity differs")
        axis_fields=("policy","process_state","page_cache_state","output_format","execution_route")
        for field in axis_fields:
            if not isinstance(before.get(field),str) or not before.get(field): raise PerformanceContractError(f"{workload_id}: baseline {field} is missing")
            if after.get(field)!=before.get(field): raise PerformanceContractError(f"{workload_id}: candidate {field} differs from baseline")
        if before["process_state"] not in {"cold","warm","steady"}: raise PerformanceContractError(f"{workload_id}: process_state is not cold, warm, or steady")
        if before.get("parity_ok") is not True:
            violations.append(f"{workload_id}: baseline finding parity is not proven")
        if after.get("parity_ok") is not True:
            violations.append(f"{workload_id}: candidate finding parity is not proven")
        baseline_wall = _positive(before, "p50_wall_ms", f"baseline {workload_id}")
        candidate_wall = _positive(after, "p50_wall_ms", f"candidate {workload_id}")
        speedup = baseline_wall / candidate_wall
        if speedup < speed_floor:
            violations.append(
                f"{workload_id}: speedup {speedup:.6f}x is below {speed_floor:.6f}x"
            )
        baseline_rss = _positive(before, "max_peak_rss_kb", f"baseline {workload_id}")
        candidate_rss = _positive(after, "max_peak_rss_kb", f"candidate {workload_id}")
        rss_ratio = candidate_rss / baseline_rss
        if rss_ratio > catalog.targets.max_rss_ratio:
            violations.append(
                f"{workload_id}: peak RSS ratio {rss_ratio:.6f} exceeds "
                f"{catalog.targets.max_rss_ratio:.6f}"
            )
        if backend in {"cpu", "simd"} and candidate_rss * 1024 > catalog.targets.cpu_simd_max_rss_bytes:
            violations.append(
                f"{workload_id}: peak RSS {int(candidate_rss*1024)} bytes exceeds "
                f"CPU/SIMD ceiling {catalog.targets.cpu_simd_max_rss_bytes}"
            )
        if gpu and workload.gpu_eligible:
            baseline_vram=_positive(before,"max_peak_vram_bytes",f"baseline {workload_id}")
            candidate_vram=_positive(after,"max_peak_vram_bytes",f"candidate {workload_id}")
            vram_ratio=candidate_vram/baseline_vram
            if vram_ratio>catalog.targets.max_vram_ratio:
                violations.append(f"{workload_id}: device VRAM ratio {vram_ratio:.6f} exceeds {catalog.targets.max_vram_ratio:.6f}")
        if workload.betterleaks_comparable:
            competitor = competitor_rows.get(workload_id)
            if competitor is None:
                if betterleaks is not None:
                    violations.append(f"{workload_id}: Betterleaks evidence is missing")
                continue
            if (
                competitor.get("fixture_input_sha256") != after.get("fixture_input_sha256")
                or competitor.get("fixture_answer_sha256") != after.get("fixture_answer_sha256")
            ):
                raise PerformanceContractError(
                    f"{workload_id}: Betterleaks and candidate fixture identity differs"
                )
            if competitor.get("parity_ok") is not True:
                violations.append(f"{workload_id}: Betterleaks finding parity is not proven")
            competitor_wall = _positive(
                competitor, "p50_wall_ms", f"Betterleaks {workload_id}"
            )
            ratio = candidate_wall / competitor_wall
            if ratio > catalog.targets.betterleaks_max_time_ratio:
                violations.append(
                    f"{workload_id}: Betterleaks time ratio {ratio:.6f} exceeds "
                    f"{catalog.targets.betterleaks_max_time_ratio:.6f}"
                )
            competitor_rss = _positive(
                competitor, "max_peak_rss_kb", f"Betterleaks {workload_id}"
            )
            if candidate_rss >= competitor_rss:
                violations.append(
                    f"{workload_id}: candidate peak RSS {int(candidate_rss)} KiB is not "
                    f"strictly below Betterleaks {int(competitor_rss)} KiB"
                )
    return violations
def evaluate_exhaustive_performance_gate(
    runs_by_backend: Mapping[str, tuple[Mapping[str, object], Mapping[str, object]]],
    catalog: WorkloadCatalog,
    *,
    betterleaks: Mapping[str, object] | None = None,
) -> list[str]:
    """Enforce the exhaustive performance contract across every catalog workload and backend route.

    Checks:
    1. Finding parity on every workload and backend route.
    2. Minimum 2.0x speedup for CPU/SIMD workloads.
    3. Minimum 10.0x speedup for GPU-eligible workloads.
    4. Peak RSS ratio at most 0.25 (quarter memory).
    5. CPU/SIMD peak RSS at most 128 MiB (134,217,728 bytes).
    6. BetterLeaks time ratio at most 0.25 and strictly lower max RSS for all 18 shared workloads.
    7. Device VRAM ratio at most 0.25 for GPU-eligible workloads.
    """
    violations: list[str] = []
    if not isinstance(runs_by_backend, Mapping) or not runs_by_backend:
        raise PerformanceContractError("exhaustive performance gate requires at least one backend run set")

    for backend, run_pair in sorted(runs_by_backend.items()):
        if not isinstance(run_pair, (tuple, list)) or len(run_pair) != 2:
            raise PerformanceContractError(f"backend {backend!r} run set must be a (baseline, candidate) pair")
        baseline, candidate = run_pair
        if not isinstance(baseline, Mapping) or not isinstance(candidate, Mapping):
            raise PerformanceContractError(f"backend {backend!r} baseline and candidate must be mappings")
        backend_violations = evaluate_performance_contract(
            baseline,
            candidate,
            catalog,
            betterleaks=betterleaks if backend in {"cpu", "simd"} else None,
        )
        for v in backend_violations:
            violations.append(f"[{backend}] {v}")

    return violations
