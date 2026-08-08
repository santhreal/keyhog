"""Provenance-bound Betterleaks baselines over shared canonical fixtures."""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import os
import pathlib
import tempfile
import time

from .baseline_capture import (
    BASELINE_SCHEMA_VERSION,
    MIN_TRIALS,
    BaselineCaptureError,
    BaselineTrial,
    _combine_concurrent_trials,
    _filesystem_scan_roots,
    _fixture_expectation,
    capture_target_evidence,
    runtime_fixture_state,
    sha256_file,
    summarize_trials,
)
from .scanners.base import RunStats, run_measured
from .target_matrix import load_target_matrix, target_matrix_sha256
from .workload_catalog import Workload, load_workload_catalog
from .workload_fixtures import validate_fixture_lock


def betterleaks_command(binary: pathlib.Path, target: pathlib.Path, *, stdin: bool) -> list[str]:
    """Build the non-validating Betterleaks route with unredacted machine output."""
    command = [str(binary), "stdin" if stdin else "dir", "--no-banner", "--report-format", "json", "--report-path", "-", "--redact=0", "--validation=false", "--exit-code", "0"]
    if not stdin:
        command.append(str(target))
    return command


def _trial(stdout: str, stats: RunStats) -> BaselineTrial:
    """Parse stdout and run statistics into a structured BaselineTrial."""
    if stats.timed_out or stats.exit_code != 0:
        raise BaselineCaptureError(
            f"Betterleaks exited {stats.exit_code}, timed_out={stats.timed_out}"
        )
    try:
        findings = json.loads(stdout.strip() or "[]")
    except json.JSONDecodeError as exc:
        raise BaselineCaptureError(f"Betterleaks emitted invalid JSON: {exc}") from exc
    if not isinstance(findings, list):
        raise BaselineCaptureError("Betterleaks report is not an array")
    hashes: list[str] = []
    for index, finding in enumerate(findings):
        if not isinstance(finding, dict):
            raise BaselineCaptureError(f"Betterleaks finding[{index}] is not an object")
        secret = finding.get("Secret") or finding.get("Match")
        if not isinstance(secret, str):
            raise BaselineCaptureError(f"Betterleaks finding[{index}] has no exact secret")
        hashes.append(hashlib.sha256(secret.encode()).hexdigest())
    return BaselineTrial(
        wall_ms=stats.wall_ms,
        peak_rss_kb=stats.peak_rss_kb,
        minor_page_faults=stats.minor_page_faults,
        major_page_faults=stats.major_page_faults,
        exit_code=stats.exit_code,
        finding_count=len(findings),
        finding_hashes=tuple(sorted(hashes)),
        coverage_gap_count=0,
        result_error="",
    )


def capture_betterleaks_workload(
    workload: Workload,
    *,
    binary: pathlib.Path,
    fixture_root: pathlib.Path,
    fixture_receipt: dict[str, object],
    repetitions: int,
):
    """Capture one shared filesystem, stdin, or independent-process workload."""
    if repetitions < MIN_TRIALS:
        raise BaselineCaptureError(f"baseline repetitions must be at least {MIN_TRIALS}")
    expected_hashes, expected_gap = _fixture_expectation(fixture_root)
    trials: list[BaselineTrial] = []
    with runtime_fixture_state(fixture_root):
        for _index in range(repetitions):
            if workload.family == "stdin":
                target = fixture_root / "input/stdin.bin"
                stdout, _stderr, stats = run_measured(
                    betterleaks_command(binary, target, stdin=True),
                    stdin_path=target,
                    timeout=3600,
                )
                trials.append(_trial(stdout, stats))
            elif workload.family == "filesystem":
                roots = _filesystem_scan_roots(workload, fixture_root)
                if len(roots) != 1:
                    raise BaselineCaptureError(
                        f"Betterleaks shared workload {workload.workload_id} has {len(roots)} roots"
                    )
                stdout, _stderr, stats = run_measured(
                    betterleaks_command(binary, pathlib.Path(roots[0]), stdin=False),
                    timeout=3600,
                )
                trials.append(_trial(stdout, stats))
            elif workload.family == "concurrency":
                partitions = [fixture_root / "input" / f"partition-{index}" for index in range(4)]
                started = time.perf_counter_ns()
                with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
                    futures = [
                        pool.submit(
                            run_measured,
                            betterleaks_command(binary, partition, stdin=False),
                            timeout=3600,
                        )
                        for partition in partitions
                    ]
                    rows = [_trial(*((lambda result: (result[0], result[2]))(future.result()))) for future in futures]
                cohort_wall_ms = (time.perf_counter_ns() - started) / 1_000_000
                trials.append(_combine_concurrent_trials(cohort_wall_ms, rows))
            else:
                raise BaselineCaptureError(
                    f"Betterleaks has no shared route for {workload.family!r}"
                )
    return summarize_trials(
        workload.workload_id,
        "betterleaks",
        str(fixture_receipt["input_sha256"]),
        str(fixture_receipt["answer_sha256"]),
        sha256_file(binary),
        trials,
        expected_hashes,
        expected_gap,
    )


def capture_betterleaks_catalog(
    *,
    catalog_path: pathlib.Path,
    fixture_lock_path: pathlib.Path,
    fixture_root: pathlib.Path,
    target_matrix_path: pathlib.Path,
    target_id: str,
    binary: pathlib.Path,
    repetitions: int = MIN_TRIALS,
) -> dict[str, object]:
    """Capture every catalog row declared comparable with Betterleaks."""
    catalog = load_workload_catalog(catalog_path)
    lock = validate_fixture_lock(catalog_path, fixture_lock_path)
    matrix = load_target_matrix(target_matrix_path)
    target = next((item for item in matrix.targets if item.target_id == target_id), None)
    if target is None:
        raise BaselineCaptureError(f"target matrix does not define {target_id!r}")
    lock_rows = {row["workload_id"]: row for row in lock["workloads"]}
    workloads = [workload for workload in catalog.workloads if workload.betterleaks_comparable]
    summaries = [
        capture_betterleaks_workload(
            workload,
            binary=binary,
            fixture_root=fixture_root / workload.workload_id,
            fixture_receipt=lock_rows[workload.workload_id],
            repetitions=repetitions,
        )
        for workload in workloads
    ]
    return {
        "schema_version": BASELINE_SCHEMA_VERSION,
        "catalog_sha256": lock["catalog_sha256"],
        "fixture_lock_sha256": sha256_file(fixture_lock_path),
        "target_matrix_sha256": target_matrix_sha256(target_matrix_path),
        "target_id": target_id,
        "host_evidence": capture_target_evidence(target),
        "binary_sha256": sha256_file(binary),
        "backend": "betterleaks",
        "policy": "default",
        "process_state": "cold",
        "page_cache_state": "uncontrolled",
        "output_format": "json",
        "execution_route": "in-process",
        "repetitions": repetitions,
        "workloads": [summary.to_json() for summary in summaries],
    }


def _main() -> int:
    """Execute CLI entry point for Betterleaks baseline capture."""
    parser = argparse.ArgumentParser(description="Capture canonical Betterleaks baselines")
    parser.add_argument("--catalog", default="workload-catalog.toml")
    parser.add_argument("--fixture-lock", default="workload-fixtures.lock.json")
    parser.add_argument("--fixtures", required=True)
    parser.add_argument("--target-matrix", default="target-matrix.toml")
    parser.add_argument("--target", required=True)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--repetitions", type=int, default=MIN_TRIALS)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    payload = capture_betterleaks_catalog(
        catalog_path=pathlib.Path(args.catalog),
        fixture_lock_path=pathlib.Path(args.fixture_lock),
        fixture_root=pathlib.Path(args.fixtures),
        target_matrix_path=pathlib.Path(args.target_matrix),
        target_id=args.target,
        binary=pathlib.Path(args.binary).resolve(strict=True),
        repetitions=args.repetitions,
    )
    destination = pathlib.Path(args.out)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(f".{destination.name}.tmp-{os.getpid()}")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    temporary.replace(destination)
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
