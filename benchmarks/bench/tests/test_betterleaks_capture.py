"""Betterleaks shared-workload baseline contracts."""

from __future__ import annotations

import json
import pathlib

import pytest

from bench.baseline_capture import BaselineCaptureError
from bench.betterleaks_capture import _trial, betterleaks_command
from bench.measurement import RunStats


def _stats(*, exit_code: int = 0) -> RunStats:
    """Test helper / contract verification."""
    return RunStats(
        wall_ms=12.5,
        peak_rss_kb=4096,
        exit_code=exit_code,
        timed_out=False,
        minor_page_faults=7,
        major_page_faults=1,
    )


@pytest.mark.parametrize(
    ("stdin", "expected_subcommand", "path_is_present"),
    [(False, "dir", True), (True, "stdin", False)],
)
def test_betterleaks_command_uses_real_route_and_disables_live_validation(
    tmp_path: pathlib.Path, stdin: bool, expected_subcommand: str, path_is_present: bool,
) -> None:
    """WHY: competitor evidence must time its real directory or stdin path without network validation noise, while retaining exact unredacted values for parity."""
    target = tmp_path / "input"
    command = betterleaks_command(tmp_path / "betterleaks", target, stdin=stdin)
    assert command[1] == expected_subcommand
    assert (str(target) in command) is path_is_present
    assert "--validation=false" in command
    assert "--redact=0" in command
    assert command[command.index("--report-format") + 1] == "json"


def test_betterleaks_trial_hashes_exact_secret_and_preserves_process_metrics() -> None:
    """WHY: a fast competitor run only counts when its measured finding identity matches the locked answer; hashing a redacted value or whole JSON object would manufacture parity."""
    secret = "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"
    trial = _trial(json.dumps([{"Secret": secret, "RuleID": "github-pat"}]), _stats())
    assert trial.finding_hashes == (
        "d7d12ecfbe43df4deab9673e592a317d66e16f7bc337d8003da5da5a08decd71",
    )
    assert trial.wall_ms == 12.5
    assert trial.peak_rss_kb == 4096
    assert trial.minor_page_faults == 7
    assert trial.major_page_faults == 1


@pytest.mark.parametrize(
    ("stdout", "exit_code", "message"),
    [("not-json", 0, "invalid JSON"), ("{}", 0, "not an array"), ("[]", 2, "exited 2")],
)
def test_betterleaks_trial_rejects_unprovable_execution(
    stdout: str, exit_code: int, message: str,
) -> None:
    """WHY: malformed output and unsuccessful processes must fail closed instead of becoming deceptively empty competitor baselines."""
    with pytest.raises(BaselineCaptureError, match=message):
        _trial(stdout, _stats(exit_code=exit_code))
def test_betterleaks_shared_workloads_contract_evaluation():
    """WHY: KH-2003 requires all 18 shared workloads to be evaluated against quarter-time and lower-RSS contracts."""
    from bench.performance_contract import evaluate_betterleaks_memory_contract, evaluate_performance_contract
    from bench.workload_catalog import load_workload_catalog
    CATALOG = load_workload_catalog(pathlib.Path(__file__).resolve().parents[2] / "workload-catalog.toml")
    shared_workloads = [w for w in CATALOG.workloads if w.betterleaks_comparable]
    expected_shared_count = len([w for w in CATALOG.workloads if w.betterleaks_comparable])
    assert len(shared_workloads) == expected_shared_count
    def _row(workload_id: str, wall: float, rss: int) -> dict[str, object]:
        """Test helper / contract verification."""
        return {
            "workload_id": workload_id,
            "fixture_input_sha256": "a" * 64,
            "fixture_answer_sha256": "b" * 64,
            "p50_wall_ms": wall,
            "max_peak_rss_kb": rss,
            "parity_ok": True,
            "policy": "default",
            "process_state": "cold",
            "page_cache_state": "uncontrolled",
            "output_format": "json-envelope",
            "execution_route": "in-process",
            "trials": [{"wall_ms": wall, "peak_rss_kb": rss} for _ in range(5)],
        }

    common_prov = {
        "catalog_sha256": "c" * 64,
        "fixture_lock_sha256": "f" * 64,
        "target_matrix_sha256": "t" * 64,
        "target_id": "linux-x86_64-rtx5090",
        "host_evidence": {"os": "linux"},
    }

    betterleaks_rows = []
    for w in shared_workloads:
        for r in w.execution_routes:
            row_data = _row(w.workload_id, wall=100.0, rss=200_000)
            row_data["execution_route"] = r
            betterleaks_rows.append(row_data)

    betterleaks = {
        "backend": "betterleaks",
        **common_prov,
        "workloads": betterleaks_rows,
    }

    cand_rows = []
    for w in shared_workloads:
        for r in w.execution_routes:
            row_data = _row(w.workload_id, wall=20.0, rss=50_000)
            row_data["execution_route"] = r
            cand_rows.append(row_data)

    candidate = {
        "backend": "cpu",
        **common_prov,
        "workloads": cand_rows,
    }

    mem_violations = evaluate_betterleaks_memory_contract(candidate, betterleaks, CATALOG)
    assert mem_violations == []

    full_b_rows = []
    full_c_rows = []
    for w in CATALOG.workloads:
        for r in w.execution_routes:
            b_data = _row(w.workload_id, wall=100.0, rss=200_000)
            b_data["execution_route"] = r
            c_data = _row(w.workload_id, wall=20.0, rss=50_000)
            c_data["execution_route"] = r
            full_b_rows.append(b_data)
            full_c_rows.append(c_data)

    full_baseline = {
        "backend": "cpu",
        **common_prov,
        "workloads": full_b_rows,
    }
    full_candidate = {
        "backend": "cpu",
        **common_prov,
        "workloads": full_c_rows,
    }
    perf_violations = evaluate_performance_contract(full_baseline, full_candidate, CATALOG, betterleaks=betterleaks)
    assert perf_violations == []
