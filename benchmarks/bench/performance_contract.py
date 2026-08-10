"""Fail-closed per-workload speed, memory, parity, and competitor contracts."""

from __future__ import annotations

from collections.abc import Container, Mapping

from .baseline_capture import MIN_TRIALS
from .workload_catalog import WorkloadCatalog


class PerformanceContractError(RuntimeError):
    """Performance evidence is incomplete, stale, or incomparable."""


def _rows(payload: Mapping[str, object], label: str) -> dict[tuple[str, str], Mapping[str, object]]:
    """Extract and validate workload rows from baseline or candidate payload."""
    raw = payload.get("workloads")
    if not isinstance(raw, list):
        raise PerformanceContractError(f"{label} workloads must be an array")
    rows: dict[tuple[str, str], Mapping[str, object]] = {}
    for index, row in enumerate(raw):
        if not isinstance(row, Mapping) or not isinstance(row.get("workload_id"), str):
            raise PerformanceContractError(f"{label} workload[{index}] is malformed")
        workload_id = str(row["workload_id"])
        route = row.get("execution_route")
        if route is None or not isinstance(route, str) or not route:
            route = "in-process"
        key = (workload_id, route)
        if key in rows:
            raise PerformanceContractError(f"{label} duplicates workload route {key!r}")
        trials = row.get("trials")
        if not isinstance(trials, list) or len(trials) < MIN_TRIALS:
            raise PerformanceContractError(
                f"{label} workload {workload_id!r} has fewer than {MIN_TRIALS} trials"
            )
        rows[key] = row
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
    cand_keys = set(candidate_rows.keys())
    comp_keys = set(competitor_rows.keys())
    shared_keys = {
        (workload.workload_id, route)
        for workload in catalog.workloads
        if workload.betterleaks_comparable
        for route in workload.execution_routes
    }
    expected_comp_ids = {w for w, _ in shared_keys}
    cand_comp_workload_ids = {w for w, _ in cand_keys if w in expected_comp_ids}
    if cand_comp_workload_ids != expected_comp_ids:
        missing = sorted(expected_comp_ids - cand_comp_workload_ids)
        extra = sorted(cand_comp_workload_ids - expected_comp_ids)
        raise PerformanceContractError(
            f"candidate shared coverage differs: missing={missing}, extra={extra}"
        )
    comp_workload_ids = {w for w, _ in comp_keys}
    if comp_workload_ids != expected_comp_ids:
        missing = sorted(expected_comp_ids - comp_workload_ids)
        extra = sorted(comp_workload_ids - expected_comp_ids)
        raise PerformanceContractError(
            f"Betterleaks shared coverage differs: missing={missing}, extra={extra}"
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
    for workload_id, route in sorted(shared_keys):
        after = candidate_rows[(workload_id, route)]
        competitor = competitor_rows.get((workload_id, route)) or competitor_rows.get((workload_id, "in-process"))
        if competitor is None:
            raise PerformanceContractError(f"{workload_id}: Betterleaks evidence is missing for route {route!r}")
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
    expected = {
        (workload.workload_id, route)
        for workload in catalog.workloads
        for route in workload.execution_routes
    }
    baseline_keys = set(baseline_rows)
    if baseline_keys != expected:
        missing = sorted(expected - baseline_keys)
        extra = sorted(baseline_keys - expected)
        raise PerformanceContractError(
            f"baseline coverage differs: missing={missing}, extra={extra}"
        )
    candidate_keys = set(candidate_rows)
    if candidate_keys != expected:
        missing = sorted(expected - candidate_keys)
        extra = sorted(candidate_keys - expected)
        raise PerformanceContractError(
            f"candidate coverage differs: missing={missing}, extra={extra}"
        )
    backend = candidate.get("backend")
    if not isinstance(backend, str):
        raise PerformanceContractError("candidate backend is missing")
    gpu = backend.startswith("gpu-")
    speed_floor = catalog.targets.gpu_min_speedup if gpu else catalog.targets.min_speedup
    competitor_rows = _rows(betterleaks, "betterleaks") if betterleaks is not None else {}
    if betterleaks is not None:
        provenance_fields = (
            "catalog_sha256", "fixture_lock_sha256", "target_matrix_sha256",
            "target_id", "host_evidence",
        )
        for field in provenance_fields:
            if candidate.get(field) is not None and betterleaks.get(field) is not None:
                if candidate.get(field) != betterleaks.get(field):
                    raise PerformanceContractError(
                        f"candidate and Betterleaks {field} provenance differs"
                    )
        shared_comp_ids = {
            workload.workload_id
            for workload in catalog.workloads
            if workload.betterleaks_comparable
        }
        actual_comp_ids = {w for w, _ in competitor_rows.keys()}
        if actual_comp_ids != shared_comp_ids:
            raise PerformanceContractError(
                "Betterleaks coverage differs: "
                f"missing={sorted(shared_comp_ids-actual_comp_ids)}, "
                f"extra={sorted(actual_comp_ids-shared_comp_ids)}"
            )
    violations: list[str] = []
    workload_map = {workload.workload_id: workload for workload in catalog.workloads}
    for key in sorted(candidate_rows.keys()):
        workload_id, route = key
        workload = workload_map[workload_id]
        before = baseline_rows[key]
        after = candidate_rows[key]
        if (
            before.get("fixture_input_sha256") != after.get("fixture_input_sha256")
            or before.get("fixture_answer_sha256") != after.get("fixture_answer_sha256")
        ):
            raise PerformanceContractError(f"{workload_id}: baseline and candidate fixture identity differs")
        axis_fields = ("policy", "process_state", "page_cache_state", "output_format", "execution_route")
        for field in axis_fields:
            if not isinstance(before.get(field), str) or not before.get(field):
                raise PerformanceContractError(f"{workload_id}: baseline {field} is missing")
            if after.get(field) != before.get(field):
                raise PerformanceContractError(f"{workload_id}: candidate {field} differs from baseline")
        if before["process_state"] not in {"cold", "warm", "steady"}:
            raise PerformanceContractError(f"{workload_id}: process_state is not cold, warm, or steady")
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
            baseline_vram = _positive(before, "max_peak_vram_bytes", f"baseline {workload_id}")
            candidate_vram = _positive(after, "max_peak_vram_bytes", f"candidate {workload_id}")
            vram_ratio = candidate_vram / baseline_vram
            if vram_ratio > catalog.targets.max_vram_ratio:
                violations.append(
                    f"{workload_id}: device VRAM ratio {vram_ratio:.6f} exceeds {catalog.targets.max_vram_ratio:.6f}"
                )
        if workload.betterleaks_comparable:
            competitor = competitor_rows.get(key) or competitor_rows.get((workload_id, "in-process"))
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
    required_backends: Container[str] | None = None,
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

    if required_backends is not None:
        expected_backends = set(required_backends)
    else:
        gpu_backends = {b for b in catalog.dimensions.backends if b.startswith("gpu-")}
        if any(w.gpu_eligible for w in catalog.workloads):
            supplied_gpus = {b for b in runs_by_backend if b.startswith("gpu-")}
            if supplied_gpus:
                expected_backends = {"cpu", "simd"} | supplied_gpus
            else:
                expected_backends = {"cpu", "simd"} | gpu_backends
        else:
            expected_backends = {"cpu", "simd"}

    if set(runs_by_backend.keys()) != expected_backends:
        missing = sorted(expected_backends - set(runs_by_backend.keys()))
        extra = sorted(set(runs_by_backend.keys()) - expected_backends)
        raise PerformanceContractError(
            f"exhaustive performance gate backend coverage differs: missing={missing}, extra={extra}"
        )
    for backend, run_pair in sorted(runs_by_backend.items()):
        if not isinstance(run_pair, (tuple, list)) or len(run_pair) != 2:
            raise PerformanceContractError(f"backend {backend!r} run set must be a (baseline, candidate) pair")
        baseline, candidate = run_pair
        if not isinstance(baseline, Mapping) or not isinstance(candidate, Mapping):
            raise PerformanceContractError(f"backend {backend!r} baseline and candidate must be mappings")
        if baseline.get("backend") != backend or candidate.get("backend") != backend:
            raise PerformanceContractError(
                f"backend {backend!r} run set has mismatched backend field: "
                f"baseline={baseline.get('backend')!r}, candidate={candidate.get('backend')!r}"
            )

        if backend in {"cpu", "simd"} and betterleaks is not None:
            bl_mem_violations = evaluate_betterleaks_memory_contract(candidate, betterleaks, catalog)
            for v in bl_mem_violations:
                if f"[{backend}] {v}" not in violations:
                    violations.append(f"[{backend}] {v}")

        backend_violations = evaluate_performance_contract(
            baseline,
            candidate,
            catalog,
            betterleaks=betterleaks if backend in {"cpu", "simd"} else None,
        )
        for v in backend_violations:
            violations.append(f"[{backend}] {v}")

    return violations
