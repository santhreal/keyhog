"""Whole-process baseline timing, memory, and parity contracts."""

from __future__ import annotations

from dataclasses import replace
import json
import pathlib
import sys
import socket
import ssl
import subprocess
import urllib.request

import pytest
import bench.baseline_capture as baseline_capture_module

from bench.baseline_capture import (
    BaselineCaptureError,
    BaselineTrial,
    _combine_concurrent_trials,
    _watch_finding_hashes,
    capture_baseline_catalog,
    capture_filesystem_baseline,
    concurrency_command,
    cloud_command,
    capture_stdin_baseline,
    filesystem_command,
    fixture_http_server,
    fixture_daemon_remote_server,
    fixture_s3_server,
    fixture_slack_server,
    fixture_github_collaboration_server,
    fixture_git_http_server,
    fixture_github_org_server,
    fixture_hosted_group_server,
    hosted_group_command,
    verification_connect_proxy,
    prepare_verification_detectors,
    prepare_oob_verification_detectors,
    verification_command,
    system_command,
    _parse_system_trial,
    github_org_command,
    github_collaboration_command,
    git_command,
    prepare_git_repository,
    web_command,
    merge_baseline_payloads,
    percentile_nearest_rank,
    rebind_fixture_lock,
    runtime_fixture_state,
    summarize_trials,
    sha256_file,
    validate_baseline_payload,
    workload_measurement_axes,
    exclusive_capture_lock,
    startup_profile_command,
    parse_startup_profile,
    bind_diagnostic_provenance,
)
from bench.measurement import RunStats
from bench.scanners.base import run_measured
from bench.workload_catalog import load_workload_catalog
from bench.workload_fixtures import CANARY, materialize_fixture

CATALOG_PATH = pathlib.Path(__file__).resolve().parents[2] / "workload-catalog.toml"
LOCK_PATH = pathlib.Path(__file__).resolve().parents[2] / "workload-fixtures.lock.json"
TARGET_PATH = pathlib.Path(__file__).resolve().parents[2] / "target-matrix.toml"



def _test_host_evidence(_target) -> dict[str, object]:
    """Test helper / contract verification."""
    return {
        "os": "linux", "arch": "x86_64",
        "cpu": "AMD Ryzen 9 9950X 16-Core Processor", "logical_cores": 32,
        "ram_mb": 100_000, "gpu": "NVIDIA GeForce RTX 5090",
        "gpu_vram_mb": 33_000, "gpu_driver": "580.178.04",
        "kernel": "test kernel",
    }

def _workload(workload_id: str):
    """Test helper / contract verification."""
    catalog = load_workload_catalog(CATALOG_PATH)
    return next(item for item in catalog.workloads if item.workload_id == workload_id)


def _trial(wall: float, rss: int, hashes: tuple[str, ...], gaps: int = 0) -> BaselineTrial:
    """Test helper / contract verification."""
    return BaselineTrial(
        wall_ms=wall,
        peak_rss_kb=rss,
        minor_page_faults=10,
        major_page_faults=1,
        exit_code=1 if hashes else 0,
        finding_count=len(hashes),
        finding_hashes=hashes,
        coverage_gap_count=gaps,
        result_error="",
    )


def test_nearest_rank_p95_preserves_observed_tail() -> None:
    """WHY: interpolating five noisy trials can invent a tail latency never observed; the release gate uses the actual slowest sample at p95."""
    assert percentile_nearest_rank([10, 20, 30, 40, 50], 0.95) == 50
    assert percentile_nearest_rank([50, 10, 40, 20, 30], 0.50) == 30


def test_summary_records_p50_p95_and_peak_rss_with_exact_parity() -> None:
    """WHY: speed and memory targets must consume the same exact successful finding multiset, not a faster behavior that lost duplicate file findings."""
    digest = "a" * 64
    trials = [
        _trial(10, 100, (digest, digest)),
        _trial(20, 110, (digest, digest)),
        _trial(30, 120, (digest, digest)),
        _trial(40, 130, (digest, digest)),
        _trial(50, 140, (digest, digest)),
    ]
    summary = summarize_trials(
        "filesystem-multiple-roots",
        "cpu",
        "b" * 64,
        "c" * 64,
        "d" * 64,
        trials,
        (digest, digest),
        False,
    )
    assert summary.p50_wall_ms == 30
    assert summary.p95_wall_ms == 50
    assert summary.median_peak_rss_kb == 120
    assert summary.max_peak_rss_kb == 140
    assert summary.parity_ok is True


def test_summary_rejects_duplicate_finding_loss_as_parity_failure() -> None:
    """WHY: set comparison would treat one finding and four same-secret file findings as equal, permitting a false speedup by dropping locations."""
    digest = "a" * 64
    trials = [_trial(value, 100, (digest,)) for value in (10, 11, 12, 13, 14)]
    summary = summarize_trials(
        "filesystem-multiple-roots",
        "cpu",
        "b" * 64,
        "c" * 64,
        "d" * 64,
        trials,
        (digest, digest, digest),
        False,
    )
    assert summary.parity_ok is False


def test_filesystem_driver_selects_only_requested_route_and_policy(tmp_path: pathlib.Path) -> None:
    """WHY: baseline commands must not initialize GPU or daemon state while claiming to measure the explicit scalar route."""
    workload = _workload("filesystem-single-large-file")
    command = filesystem_command(
        workload,
        binary=tmp_path / "keyhog",
        detectors=tmp_path / "detectors",
        fixture_root=tmp_path / "fixture",
        output=tmp_path / "result.json",
        backend="cpu",
    )
    assert command.count("--backend") == 1
    assert command[command.index("--backend") + 1] == "cpu"
    assert "--no-gpu" in command
    assert "--daemon=off" in command
    assert command[command.index("--max-file-size") + 1] == "512M"


def test_binary_filesystem_driver_targets_the_regular_file(tmp_path: pathlib.Path) -> None:
    """WHY: --binary accepts regular files, so passing the fixture directory turns a finding workload into an unreadable-source gap."""
    command = filesystem_command(
        _workload("filesystem-binary-strings"),
        binary=tmp_path / "keyhog",
        detectors=None,
        fixture_root=tmp_path / "fixture",
        output=tmp_path / "result.json",
        backend="cpu",
    )
    assert "--binary" in command
    assert command[-1] == str(tmp_path / "fixture" / "input" / "program.bin")



def test_watch_finding_hash_parser_binds_only_the_changed_path() -> None:
    """WHY: watch performance is valid parity evidence only when its redaction-safe output identifies the credential found for the measured event."""
    digest = "a" * 64
    lines = [
        f"FINDING github other.env:1 CRITICAL gh...hp sha256:{'b' * 64}\n",
        f"FINDING github event.env:1 CRITICAL gh...hp sha256:{digest}\n",
    ]
    assert _watch_finding_hashes(lines, "event.env") == (digest,)


def test_capture_runs_five_complete_process_trials_and_binds_binary(
    tmp_path: pathlib.Path,
) -> None:
    """WHY: one timed process cannot establish p50 or p95, and a result without the exact executable digest cannot serve as a before baseline."""
    workload = _workload("filesystem-single-tiny-file")
    fixture = materialize_fixture(workload, tmp_path / "fixtures")
    binary = tmp_path / "keyhog"
    binary.write_bytes(b"exact candidate bytes")
    binary.chmod(0o755)
    detectors = tmp_path / "detectors"
    detectors.mkdir()
    answers = json.loads((fixture.root / "answers.json").read_text(encoding="utf-8"))
    digest = answers[0]["credential_sha256"]
    walls = iter([50.0, 10.0, 30.0, 20.0, 40.0])
    commands: list[list[str]] = []

    def fake_runner(command):
        """Test helper / contract verification."""
        command = list(command)
        commands.append(command)
        output = pathlib.Path(command[command.index("--output") + 1])
        output.write_text(
            json.dumps(
                {
                    "findings": [{"credential_hash": digest}],
                    "coverage_gap_summary": [],
                }
            ),
            encoding="utf-8",
        )
        return "", "", RunStats(
            wall_ms=next(walls), peak_rss_kb=1234, exit_code=1, timed_out=False
        )

    receipt = json.loads((fixture.root / "fixture.json").read_text(encoding="utf-8"))
    summary = capture_filesystem_baseline(
        workload,
        binary=binary,
        detectors=detectors,
        fixture_root=fixture.root,
        fixture_receipt=receipt,
        backend="cpu",
        runner=fake_runner,
    )
    assert len(commands) == 5
    assert summary.p50_wall_ms == 30
    assert summary.p95_wall_ms == 50
    assert summary.max_peak_rss_kb == 1234
    assert summary.parity_ok is True
    assert len(summary.binary_sha256) == 64


def test_baseline_refuses_too_few_trials() -> None:
    """WHY: reducing repetitions to make a gate faster destroys the requested p95 evidence and must fail before publishing a summary."""
    with pytest.raises(BaselineCaptureError, match="at least 5 trials"):
        summarize_trials(
            "filesystem-single-tiny-file",
            "cpu",
            "a" * 64,
            "b" * 64,
            "c" * 64,
            [_trial(1, 1, tuple())] * 4,
            tuple(),
            False,
        )


def test_runtime_unreadable_state_is_applied_and_restored(tmp_path: pathlib.Path) -> None:
    """WHY: the unreadable workload must measure a real permission failure without leaving fixture cleanup permanently broken after a trial."""
    workload = _workload("filesystem-unreadable-tree")
    fixture = materialize_fixture(workload, tmp_path / "fixtures")
    locked = fixture.root / "input/locked"
    secret = locked / "secret.env"
    original_dir_mode = locked.stat().st_mode & 0o777
    original_file_mode = secret.stat().st_mode & 0o777
    with runtime_fixture_state(fixture.root):
        assert locked.stat().st_mode & 0o777 == 0
        with pytest.raises(PermissionError):
            secret.read_bytes()
    assert locked.stat().st_mode & 0o777 == original_dir_mode
    assert secret.stat().st_mode & 0o777 == original_file_mode


def test_runtime_size_mutation_restores_exact_fixture_bytes(tmp_path: pathlib.Path) -> None:
    """WHY: each changing-size repetition must begin from byte-identical files instead of inheriting the previous trial's append and truncate side effects."""
    workload = _workload("filesystem-changing-size")
    fixture = materialize_fixture(workload, tmp_path / "fixtures", scale=0.001)
    paths = [
        fixture.root / "input/changing/growing.txt",
        fixture.root / "input/changing/shrinking.txt",
    ]
    before = [path.read_bytes() for path in paths]
    with runtime_fixture_state(fixture.root):
        import time
        time.sleep(0.01)
        assert [path.read_bytes() for path in paths] != before
    assert [path.read_bytes() for path in paths] == before


def test_missing_envelope_remains_a_timed_broken_baseline(tmp_path: pathlib.Path) -> None:
    """WHY: current all-source failures omit their report; baseline capture must preserve their wall and RSS while marking parity false instead of losing the entire matrix."""
    workload = _workload("filesystem-over-size-limit")
    fixture = materialize_fixture(workload, tmp_path / "fixtures", scale=0.001)
    binary = tmp_path / "keyhog"
    binary.write_bytes(b"candidate")
    binary.chmod(0o755)
    detectors = tmp_path / "detectors"
    detectors.mkdir()

    def missing_report_runner(_command):
        """Test helper / contract verification."""
        return "", "", RunStats(wall_ms=12.5, peak_rss_kb=4321, exit_code=13, timed_out=False)

    receipt = json.loads((fixture.root / "fixture.json").read_text(encoding="utf-8"))
    summary = capture_filesystem_baseline(
        workload, binary=binary, detectors=detectors, fixture_root=fixture.root,
        fixture_receipt=receipt, backend="cpu", runner=missing_report_runner,
    )
    assert summary.p50_wall_ms == 12.5
    assert summary.max_peak_rss_kb == 4321
    assert summary.parity_ok is False
    assert all("no valid envelope" in trial.result_error for trial in summary.trials)


def test_run_measured_streams_binary_stdin_from_fixture_path(tmp_path: pathlib.Path) -> None:
    """WHY: stdin benchmarks must feed the measured child process itself, including arbitrary bytes, rather than timing an empty pipe or a pre-read Python buffer."""
    source = tmp_path / "input.bin"
    source.write_bytes(b"a\x00b\xffc")
    stdout, stderr, stats = run_measured(
        [sys.executable, "-c", "import sys; print(len(sys.stdin.buffer.read()))"],
        stdin_path=source,
    )
    assert stdout.strip() == "5"
    assert stderr == ""
    assert stats.exit_code == 0
    assert stats.peak_rss_kb > 0
    assert stats.minor_page_faults is not None and stats.minor_page_faults > 0
    assert stats.major_page_faults is not None and stats.major_page_faults >= 0


def test_stdin_capture_feeds_exact_canonical_bytes_for_all_trials(
    tmp_path: pathlib.Path,
) -> None:
    """WHY: stdin timing is valid only when each whole-process trial consumes the exact digest-bound fixture and proves the expected credential result."""
    workload = _workload("stdin-medium")
    fixture = materialize_fixture(workload, tmp_path / "fixtures")
    binary = tmp_path / "keyhog"
    binary.write_bytes(b"candidate")
    binary.chmod(0o755)
    detectors = tmp_path / "detectors"
    detectors.mkdir()
    answer = json.loads((fixture.root / "answers.json").read_text(encoding="utf-8"))[0]
    observed_sizes: list[int] = []

    def fake_runner(command, source):
        """Test helper / contract verification."""
        observed_sizes.append(source.stat().st_size)
        output = pathlib.Path(command[command.index("--output") + 1])
        output.write_text(json.dumps({
            "findings": [{"credential_hash": answer["credential_sha256"]}],
            "coverage_gap_summary": [],
        }), encoding="utf-8")
        return "", "", RunStats(wall_ms=25, peak_rss_kb=2000, exit_code=1, timed_out=False)

    receipt = json.loads((fixture.root / "fixture.json").read_text(encoding="utf-8"))
    summary = capture_stdin_baseline(
        workload, binary=binary, detectors=detectors, fixture_root=fixture.root,
        fixture_receipt=receipt, backend="cpu", runner=fake_runner,
    )
    assert observed_sizes == [64 * 1024] * 5
    assert summary.parity_ok is True
    assert summary.p50_wall_ms == 25


def test_catalog_baseline_binds_the_exact_pinned_target_matrix(tmp_path: pathlib.Path) -> None:
    """WHY: timing from an unnamed host cannot satisfy a hardware-specific release target or be compared reproducibly after target definitions change."""
    binary = tmp_path / "keyhog"
    binary.write_bytes(b"candidate")
    payload = capture_baseline_catalog(
        catalog_path=CATALOG_PATH, fixture_lock_path=LOCK_PATH, fixture_root=tmp_path,
        target_matrix_path=TARGET_PATH, target_id="linux-x86_64-rtx5090",
        binary=binary, detectors=tmp_path, backend="cpu", only=set(),
        host_probe=_test_host_evidence,
    )
    assert payload["target_id"] == "linux-x86_64-rtx5090"
    assert len(payload["target_matrix_sha256"]) == 64
    with pytest.raises(BaselineCaptureError, match="does not define"):
        capture_baseline_catalog(
            catalog_path=CATALOG_PATH, fixture_lock_path=LOCK_PATH, fixture_root=tmp_path,
            target_matrix_path=TARGET_PATH, target_id="invented-host", binary=binary,
            detectors=tmp_path, backend="cpu", only=set(),
        )


def test_baseline_validator_recomputes_statistics_and_exact_coverage(
    tmp_path: pathlib.Path,
) -> None:
    """WHY: edited summary numbers and omitted slow workloads must not pass merely because an artifact retains valid-looking provenance hashes."""
    binary = tmp_path / "keyhog"
    binary.write_bytes(b"candidate")
    payload = capture_baseline_catalog(
        catalog_path=CATALOG_PATH, fixture_lock_path=LOCK_PATH, fixture_root=tmp_path,
        target_matrix_path=TARGET_PATH, target_id="linux-x86_64-rtx5090",
        binary=binary, detectors=tmp_path, backend="cpu", only=set(),
        host_probe=_test_host_evidence,
    )
    lock = json.loads(LOCK_PATH.read_text(encoding="utf-8"))
    receipt = next(row for row in lock["workloads"] if row["workload_id"] == "filesystem-single-tiny-file")
    trials = [_trial(wall, 1000 + wall, tuple()) for wall in (10, 20, 30, 40, 50)]
    summary = summarize_trials(
        "filesystem-single-tiny-file", "cpu", receipt["input_sha256"],
        receipt["answer_sha256"], payload["binary_sha256"], trials, tuple(), False,
    )
    row = summary.to_json(); row.update(workload_measurement_axes(_workload("filesystem-single-tiny-file"))); payload["workloads"] = [row]
    validate_baseline_payload(
        payload, catalog_path=CATALOG_PATH, fixture_lock_path=LOCK_PATH,
        target_matrix_path=TARGET_PATH, expected_workload_ids={"filesystem-single-tiny-file"},
    )
    payload["host_evidence"]["cpu"] = "different cpu"
    with pytest.raises(BaselineCaptureError, match="host evidence differs"):
        validate_baseline_payload(
            payload, catalog_path=CATALOG_PATH, fixture_lock_path=LOCK_PATH,
            target_matrix_path=TARGET_PATH, expected_workload_ids={"filesystem-single-tiny-file"},
        )
    payload["host_evidence"] = _test_host_evidence(None)
    payload["workloads"][0]["p95_wall_ms"] = 1
    with pytest.raises(BaselineCaptureError, match="p95_wall_ms does not match"):
        validate_baseline_payload(
            payload, catalog_path=CATALOG_PATH, fixture_lock_path=LOCK_PATH,
            target_matrix_path=TARGET_PATH, expected_workload_ids={"filesystem-single-tiny-file"},
        )


def test_baseline_merge_rejects_duplicate_rows_and_provenance_drift(
    tmp_path: pathlib.Path,
) -> None:
    """WHY: sharded long-running captures must never double-count a quick row or combine results from different binaries into one current baseline."""
    binary = tmp_path / "keyhog"
    binary.write_bytes(b"candidate")
    payload = capture_baseline_catalog(
        catalog_path=CATALOG_PATH, fixture_lock_path=LOCK_PATH, fixture_root=tmp_path,
        target_matrix_path=TARGET_PATH, target_id="linux-x86_64-rtx5090",
        binary=binary, detectors=tmp_path, backend="cpu", only=set(),
        host_probe=_test_host_evidence,
    )
    payload["workloads"] = [{"workload_id": "filesystem-single-tiny-file"}]
    with pytest.raises(BaselineCaptureError, match="duplicates"):
        merge_baseline_payloads([payload, payload])
    other = dict(payload)
    other["workloads"] = []
    other["binary_sha256"] = "0" * 64
    with pytest.raises(BaselineCaptureError, match="binary_sha256"):
        merge_baseline_payloads([payload, other])


def test_git_fixture_preparation_builds_exact_staged_and_history_states(
    tmp_path: pathlib.Path,
) -> None:
    """WHY: timing a plain directory under Git workload names would never execute index or commit-history acquisition and would produce meaningless route baselines."""
    staged_workload = _workload("git-staged-index")
    staged_fixture = materialize_fixture(staged_workload, tmp_path / "fixtures")
    staged_repo = prepare_git_repository(staged_workload, staged_fixture.root, tmp_path / "staged")
    staged_names = subprocess.run(
        ["git", "-C", str(staged_repo), "diff", "--cached", "--name-only"],
        check=True, capture_output=True, text=True,
    ).stdout.splitlines()
    assert staged_names == ["secret.env"]

    history_workload = _workload("git-commit-history")
    history_fixture = materialize_fixture(history_workload, tmp_path / "fixtures")
    history_repo = prepare_git_repository(history_workload, history_fixture.root, tmp_path / "history")
    commits = subprocess.run(
        ["git", "-C", str(history_repo), "rev-list", "--count", "HEAD"],
        check=True, capture_output=True, text=True,
    ).stdout.strip()
    assert commits == "3"
    assert not (history_repo / "secret.env").exists()


def test_git_commands_select_the_declared_acquisition_surface(tmp_path: pathlib.Path) -> None:
    """WHY: each Git row must invoke its production source adapter rather than silently fall back to filesystem walking of the prepared repository."""
    expected_flags = {
        "git-staged-index": "--git-staged", "git-diff-lines": "--git-diff",
        "git-reachable-blobs": "--git-blobs", "git-commit-history": "--git-history",
        "git-shallow-clone": "--git-history",
    }
    for workload_id, flag in expected_flags.items():
        command = git_command(
            _workload(workload_id), binary=tmp_path / "keyhog",
            detectors=tmp_path / "detectors", repository=tmp_path / "repo",
            output=tmp_path / "result.json", backend="cpu",
        )
        assert flag in command
        assert "--no-gpu" in command
        assert "--daemon=off" in command


def test_fixture_rebind_recomputes_oracle_parity_without_retiming(
    tmp_path: pathlib.Path,
) -> None:
    """WHY: correcting coverage-gap metadata must preserve expensive timing samples only when input and answer digests are byte-identical, then recompute parity from the corrected oracle."""
    workload = _workload("stdin-empty")
    materialize_fixture(workload, tmp_path / "fixtures")
    binary = tmp_path / "keyhog"
    binary.write_bytes(b"candidate")
    payload = capture_baseline_catalog(
        catalog_path=CATALOG_PATH, fixture_lock_path=LOCK_PATH, fixture_root=tmp_path,
        target_matrix_path=TARGET_PATH, target_id="linux-x86_64-rtx5090",
        binary=binary, detectors=tmp_path, backend="cpu", only=set(),
        host_probe=_test_host_evidence,
    )
    lock = json.loads(LOCK_PATH.read_text(encoding="utf-8"))
    receipt = next(row for row in lock["workloads"] if row["workload_id"] == workload.workload_id)
    trials = [_trial(wall, 1000, tuple(), gaps=1) for wall in (10, 20, 30, 40, 50)]
    summary = summarize_trials(
        workload.workload_id, "cpu", receipt["input_sha256"], receipt["answer_sha256"],
        payload["binary_sha256"], trials, tuple(), False,
    )
    assert summary.parity_ok is False
    row = summary.to_json(); row.update(workload_measurement_axes(_workload("filesystem-single-tiny-file"))); payload["workloads"] = [row]
    rebound = rebind_fixture_lock(
        payload, fixture_lock_path=LOCK_PATH, fixture_root=tmp_path / "fixtures",
    )
    assert rebound["workloads"][0]["parity_ok"] is True
    payload["workloads"][0]["fixture_input_sha256"] = "0" * 64
    with pytest.raises(BaselineCaptureError, match="input or answer bytes changed"):
        rebind_fixture_lock(
            payload, fixture_lock_path=LOCK_PATH, fixture_root=tmp_path / "fixtures",
        )


def test_fixture_http_server_and_web_command_preserve_exact_multi_url_bytes(
    tmp_path: pathlib.Path,
) -> None:
    """WHY: URL baselines must drive the real HTTP acquisition path over every declared response, not scan fixture files directly or collapse a multi-URL row to one request."""
    workload = _workload("web-multiple-urls")
    fixture = materialize_fixture(workload, tmp_path / "fixtures")
    with fixture_http_server(fixture.root) as base_url:
        command = web_command(
            workload, binary=tmp_path / "keyhog", detectors=tmp_path / "detectors",
            base_url=base_url, output=tmp_path / "result.json", backend="cpu",
            fixture_root=fixture.root,
        )
        url_index = command.index("--url")
        urls = command[url_index + 1:]
        assert len(urls) == 2
        bodies = [urllib.request.urlopen(url, timeout=2).read() for url in urls]
    assert all(CANARY.encode() in body for body in bodies)
    assert "--allow-private-cloud-endpoint" in command


def test_concurrency_cohort_uses_wall_clock_and_sums_fleet_memory() -> None:
    """WHY: taking one child's RSS or summing child durations hides the actual capacity required and latency observed when operators run independent scans concurrently."""
    first = _trial(400, 100_000, ("a" * 64,))
    second = _trial(410, 110_000, ("b" * 64,))
    third = _trial(390, 120_000, ("c" * 64,))
    fourth = _trial(405, 130_000, ("d" * 64,))
    combined = _combine_concurrent_trials(425.0, [first, second, third, fourth])
    assert combined.wall_ms == 425.0
    assert combined.peak_rss_kb == 460_000
    assert combined.finding_count == 4
    assert combined.finding_hashes == tuple(sorted(("a" * 64, "b" * 64, "c" * 64, "d" * 64)))
    assert combined.minor_page_faults == 40


def test_concurrency_command_is_an_explicit_independent_process_route(tmp_path: pathlib.Path) -> None:
    """WHY: concurrency evidence must launch four ordinary production scans, not emulate partitioning inside one process with shared initialization and memory."""
    command = concurrency_command(
        _workload("concurrency-independent-partitions"), binary=tmp_path / "keyhog",
        detectors=tmp_path / "detectors", partition=tmp_path / "partition-0",
        output=tmp_path / "result.json", backend="simd",
    )
    assert command[command.index("--backend") + 1] == "simd"
    assert "--daemon=off" in command
    assert command[-1] == str(tmp_path / "partition-0")


def test_s3_fixture_server_exposes_listing_and_exact_object_bytes(tmp_path: pathlib.Path) -> None:
    """WHY: an S3 baseline must execute both production list and object GET phases; serving only payload bytes bypasses pagination and object metadata parsing."""
    workload = _workload("cloud-s3-bucket")
    fixture = materialize_fixture(workload, tmp_path / "fixtures")
    with fixture_s3_server(fixture.root) as endpoint:
        listing = urllib.request.urlopen(
            f"{endpoint}/benchmark?list-type=2", timeout=2
        ).read()
        body = urllib.request.urlopen(
            f"{endpoint}/benchmark/secret.env", timeout=2
        ).read()
        command = cloud_command(
            workload, binary=tmp_path / "keyhog", detectors=tmp_path / "detectors",
            endpoint=endpoint, output=tmp_path / "result.json", backend="cpu",
        )
    assert b"<Key>secret.env</Key>" in listing
    assert body == f"GITHUB_TOKEN={CANARY}\n".encode()
    assert "--s3-bucket" in command
    assert "--allow-private-cloud-endpoint" in command


def test_cloud_fixture_server_exposes_gcs_and_azure_protocols(tmp_path: pathlib.Path) -> None:
    """WHY: GCS and Azure rows must parse their own listing schemas and media paths instead of inheriting S3-shaped bytes behind different labels."""
    gcs = materialize_fixture(_workload("cloud-gcs-bucket"), tmp_path / "fixtures")
    with fixture_s3_server(gcs.root) as endpoint:
        gcs_listing = urllib.request.urlopen(
            f"{endpoint}/storage/v1/b/benchmark/o?alt=json&maxResults=1000", timeout=2
        ).read()
        gcs_body = urllib.request.urlopen(
            f"{endpoint}/storage/v1/b/benchmark/o/secret.env?alt=media", timeout=2
        ).read()
        gcs_command = cloud_command(
            _workload("cloud-gcs-bucket"), binary=tmp_path / "keyhog",
            detectors=tmp_path / "detectors", endpoint=endpoint,
            output=tmp_path / "gcs.json", backend="cpu",
        )
        azure_listing = urllib.request.urlopen(
            f"{endpoint}/container?restype=container&comp=list", timeout=2
        ).read()
        azure_body = urllib.request.urlopen(
            f"{endpoint}/container/secret.env", timeout=2
        ).read()
        azure_command = cloud_command(
            _workload("cloud-azure-container"), binary=tmp_path / "keyhog",
            detectors=tmp_path / "detectors", endpoint=endpoint,
            output=tmp_path / "azure.json", backend="cpu",
        )
    assert json.loads(gcs_listing)["items"][0]["name"] == "secret.env"
    assert b"<Name>secret.env</Name>" in azure_listing
    assert gcs_body == azure_body == f"GITHUB_TOKEN={CANARY}\n".encode()
    assert "--gcs-endpoint" in gcs_command
    assert "--azure-container-url" in azure_command


def test_slack_fixture_server_exposes_channel_and_exact_message(tmp_path: pathlib.Path) -> None:
    """WHY: Slack timing must exercise production workspace enumeration and message history acquisition; scanning the fixture JSON as a local file bypasses both expensive API phases."""
    fixture = materialize_fixture(_workload("slack-workspace-messages"), tmp_path / "fixtures")
    with fixture_slack_server(fixture.root) as endpoint:
        channels = json.loads(urllib.request.urlopen(f"{endpoint}/conversations.list", timeout=2).read())
        history = json.loads(urllib.request.urlopen(f"{endpoint}/conversations.history?channel=C1", timeout=2).read())
    assert channels == {"ok": True, "channels": [{"id": "C1", "name": "general"}], "response_metadata": {"next_cursor": ""}}
    assert history["messages"][0]["text"] == f"GITHUB_TOKEN={CANARY}"
    assert history["has_more"] is False


@pytest.mark.parametrize("workload_id,flag", [
    ("github-collaboration-issues", "--github-issues"),
    ("github-collaboration-pull-requests", "--github-pull-requests"),
    ("github-collaboration-discussions", "--github-discussions"),
    ("github-collaboration-gists", "--github-gists"),
    ("github-collaboration-releases", "--github-releases"),
])
def test_github_collaboration_command_binds_surface_and_explicit_endpoint(tmp_path: pathlib.Path, workload_id: str, flag: str) -> None:
    """WHY: collaboration rows must time only their named production surface against a provenance-bound endpoint; --github-all would conflate six independent acquisition costs."""
    command = github_collaboration_command(_workload(workload_id), binary=tmp_path / "keyhog", detectors=tmp_path / "detectors", endpoint="http://127.0.0.1:4321", output=tmp_path / "result.json", backend="simd")
    assert flag in command
    assert "--github-all" not in command
    assert command[command.index("--github-api-endpoint") + 1] == "http://127.0.0.1:4321"
    assert "--allow-private-cloud-endpoint" in command


def test_github_issue_fixture_server_exposes_exact_api_body(tmp_path: pathlib.Path) -> None:
    """WHY: issue timing must exercise GitHub list and comment acquisition while keeping the locked credential bytes in the issue body, not in an unrelated local file scan."""
    workload = _workload("github-collaboration-issues")
    fixture = materialize_fixture(workload, tmp_path / "fixtures")
    with fixture_github_collaboration_server(fixture.root, workload.workload_id) as endpoint:
        issues = json.loads(urllib.request.urlopen(f"{endpoint}/repos/acme/rocket/issues?state=all", timeout=2).read())
        comments = json.loads(urllib.request.urlopen(f"{endpoint}/repos/acme/rocket/issues/7/comments", timeout=2).read())
    assert issues[0]["body"] == f"GITHUB_TOKEN={CANARY}"
    assert comments == []


def test_github_wiki_command_requires_and_binds_explicit_clone_url(tmp_path: pathlib.Path) -> None:
    """WHY: wiki timing must clone the locked local revision history; silently falling back to github.com would measure network availability and unrelated repository state."""
    workload = _workload("github-collaboration-wiki")
    with pytest.raises(BaselineCaptureError, match="explicit clone URL"):
        github_collaboration_command(workload, binary=tmp_path / "keyhog", detectors=tmp_path / "detectors", endpoint="http://127.0.0.1:1", output=tmp_path / "result.json", backend="cpu")
    command = github_collaboration_command(workload, binary=tmp_path / "keyhog", detectors=tmp_path / "detectors", endpoint="http://127.0.0.1:1", output=tmp_path / "result.json", backend="cpu", wiki_url="file:///fixture/wiki")
    assert "--github-wiki" in command
    assert command[command.index("--github-wiki-url") + 1] == "file:///fixture/wiki"


def test_wiki_fixture_server_supports_real_http_clone(tmp_path: pathlib.Path) -> None:
    """WHY: wiki evidence must include Git clone acquisition; a file URL or direct repository scan bypasses transport setup and materially understates the production route."""
    source = tmp_path / "source"; source.mkdir()
    subprocess.run(["git", "-C", str(source), "init", "--quiet", "--initial-branch=main"], check=True)
    subprocess.run(["git", "-C", str(source), "config", "user.name", "Benchmark"], check=True)
    subprocess.run(["git", "-C", str(source), "config", "user.email", "benchmark@invalid"], check=True)
    (source / "Home.md").write_text(f"GITHUB_TOKEN={CANARY}\n")
    subprocess.run(["git", "-C", str(source), "add", "Home.md"], check=True)
    subprocess.run(["git", "-C", str(source), "commit", "--quiet", "-m", "wiki"], check=True)
    served = tmp_path / "served"; served.mkdir(); clone = tmp_path / "clone"
    with fixture_git_http_server(source, served) as url:
        completed = subprocess.run(["git", "clone", "--quiet", url, str(clone)], capture_output=True, text=True)
    assert completed.returncode == 0, completed.stderr
    assert (clone / "Home.md").read_text() == f"GITHUB_TOKEN={CANARY}\n"


def test_github_org_fixture_binds_listing_and_clone_to_same_origin(tmp_path: pathlib.Path) -> None:
    """WHY: organization baselines must measure authenticated listing plus repository acquisition while origin binding prevents a fixture API from redirecting credentials to another host."""
    workload=_workload("github-organization-repositories"); fixture=materialize_fixture(workload,tmp_path/"fixtures"); served=tmp_path/"served"
    with fixture_github_org_server(fixture.root,served) as endpoint:
        repos=json.loads(urllib.request.urlopen(f"{endpoint}/orgs/acme/repos?per_page=100&page=1",timeout=2).read()); clone=tmp_path/"clone"
        completed=subprocess.run(["git","clone","--quiet","--depth","1",repos[0]["clone_url"],str(clone)],capture_output=True,text=True)
        command=github_org_command(binary=tmp_path/"keyhog",detectors=tmp_path/"detectors",endpoint=endpoint,output=tmp_path/"result.json",backend="cpu")
    assert completed.returncode == 0,completed.stderr
    assert (clone/"secret.env").read_text()==f"GITHUB_TOKEN={CANARY}\n"
    assert command[command.index("--github-api-endpoint")+1]==endpoint
    assert "--allow-private-cloud-endpoint" in command


@pytest.mark.parametrize("workload_id,api_path,clone_reader", [
    ("gitlab-group-projects","/api/v4/groups/acme/projects?include_subgroups=true",lambda payload:payload[0]["http_url_to_repo"]),
    ("bitbucket-workspace-repositories","/2.0/repositories/acme?pagelen=100",lambda payload:payload["values"][0]["links"]["clone"][0]["href"]),
])
def test_hosted_group_fixture_lists_and_shallow_clones_same_origin(tmp_path:pathlib.Path,workload_id:str,api_path:str,clone_reader) -> None:
    """WHY: GitLab and Bitbucket evidence must include provider-specific listing plus a same-origin shallow clone; relabeling one generic API response would bypass each adapter's parser and origin gate."""
    workload=_workload(workload_id); fixture=materialize_fixture(workload,tmp_path/"fixtures"); served=tmp_path/f"served-{workload.family}"
    with fixture_hosted_group_server(fixture.root,served,workload.family) as endpoint:
        payload=json.loads(urllib.request.urlopen(endpoint+api_path,timeout=2).read()); clone=tmp_path/f"clone-{workload.family}"
        completed=subprocess.run(["git","clone","--quiet","--depth","1",clone_reader(payload),str(clone)],capture_output=True,text=True)
        command=hosted_group_command(workload,binary=tmp_path/"keyhog",detectors=tmp_path/"detectors",endpoint=endpoint,output=tmp_path/f"{workload.family}.json",backend="simd")
    assert completed.returncode==0,completed.stderr
    assert (clone/"secret.env").read_text()==f"GITHUB_TOKEN={CANARY}\n"
    assert any(value.startswith(endpoint) for value in command)
    assert "--allow-private-cloud-endpoint" in command


def test_verification_connect_proxy_requires_real_tls_bearer_request(tmp_path:pathlib.Path) -> None:
    """WHY: verification timing must include the production HTTPS request; a mock that only returns a verdict without CONNECT, TLS, and bearer authentication would omit the expensive and security-critical path."""
    with verification_connect_proxy(tmp_path) as (proxy,state):
        host_port=proxy.removeprefix("http://").split(":"); raw=socket.create_connection((host_port[0],int(host_port[1])),timeout=3)
        raw.sendall(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"); response=raw.recv(4096); assert response.startswith(b"HTTP/1.1 200")
        context=ssl._create_unverified_context(); tunnel=context.wrap_socket(raw,server_hostname="example.com")
        tunnel.sendall(b"GET /verify HTTP/1.1\r\nHost: example.com\r\nAuthorization: Bearer benchmark-secret\r\nConnection: close\r\n\r\n"); body=b""
        while True:
            chunk=tunnel.recv(4096)
            if not chunk: break
            body+=chunk
    assert b"200 OK" in body and b'"login":"benchmark"' in body
    assert state["requests"]==1


@pytest.mark.parametrize("workload_id,flag", [("verification-live-credentials",None),("verification-batched-service","--verify-batch")])
def test_verification_command_uses_controlled_detector_and_route(tmp_path:pathlib.Path,workload_id:str,flag:str|None) -> None:
    """WHY: live and batched rows must use a verifier-enabled PAT detector and differ only by the production batch switch, while both retain explicit proxy and TLS policy."""
    detectors=prepare_verification_detectors(tmp_path/"detectors"); text=(detectors/"github-classic-pat.toml").read_text()
    assert 'url = "https://example.com/verify"' in text
    command=verification_command(_workload(workload_id),binary=tmp_path/"keyhog",detectors=detectors,fixture_root=tmp_path,proxy="http://127.0.0.1:1234",output=tmp_path/"result.json",backend="cpu")
    assert "--verify" in command and "--proxy" in command and "--insecure" in command
    assert ((flag in command) if flag else ("--verify-batch" not in command))


def test_scan_system_command_binds_explicit_root_and_backend(tmp_path:pathlib.Path) -> None:
    """WHY: system baselines must not enumerate the benchmark host or silently autoroute; both would make timing, memory, and finding identity depend on unrelated mounted disks and calibration state."""
    fixture=tmp_path/"fixture"; (fixture/"input/mounts/home").mkdir(parents=True)
    command=system_command(_workload("system-mounted-drives"),binary=tmp_path/"keyhog",detectors=tmp_path/"detectors",fixture_root=fixture,output=tmp_path/"result.json",backend="simd")
    assert command[command.index("--root")+1]==str(fixture/"input/mounts/home")
    assert command[command.index("--backend")+1]=="simd"
    assert "--no-git-history" in command


def test_scan_system_trial_requires_exact_credential_hashes(tmp_path:pathlib.Path) -> None:
    """WHY: redacted scan-system output can prove parity only through its exact credential hash; shape-only findings or redacted display text cannot identify the locked canary."""
    output=tmp_path/"result.json"; output.write_text(json.dumps([{"credential_hash":"d7d12ecfbe43df4deab9673e592a317d66e16f7bc337d8003da5da5a08decd71"}]))
    trial=_parse_system_trial(output,RunStats(wall_ms=12.0,peak_rss_kb=4096,exit_code=1,timed_out=False))
    assert trial.finding_hashes==("d7d12ecfbe43df4deab9673e592a317d66e16f7bc337d8003da5da5a08decd71",)
    output.write_text('[{"credential_hash":"redacted"}]')
    with pytest.raises(BaselineCaptureError,match="lacks a SHA-256"):
        _parse_system_trial(output,RunStats(exit_code=1))


def test_daemon_remote_fixture_serves_exact_slack_message(tmp_path:pathlib.Path) -> None:
    """WHY: remote mass-daemon evidence must acquire bytes through a real remote source adapter; pointing the daemon at the local fixture file would duplicate the filesystem workload."""
    workload=_workload("daemon-mass-remote"); fixture=materialize_fixture(workload,tmp_path/"fixtures")
    with fixture_daemon_remote_server(fixture.root) as endpoint:
        channels=json.loads(urllib.request.urlopen(endpoint+"/conversations.list",timeout=2).read()); history=json.loads(urllib.request.urlopen(endpoint+"/conversations.history?channel=C1",timeout=2).read())
    assert channels["channels"][0]["id"]=="C1"
    assert history["messages"][0]["text"]==f"GITHUB_TOKEN={CANARY}"


def test_workload_measurement_axes_preserve_resident_and_cache_routes() -> None:
    """WHY: one artifact contains heterogeneous routes; global cold/in-process metadata previously mislabeled daemon and incremental timings and made comparisons irreproducible."""
    assert workload_measurement_axes(_workload("daemon-warm-single-file"))=={"policy":"default","process_state":"warm","page_cache_state":"warm","output_format":"json-envelope","execution_route":"warm-daemon"}
    assert workload_measurement_axes(_workload("daemon-mass-remote"))["execution_route"]=="mass-daemon"
    assert workload_measurement_axes(_workload("incremental-warm-index"))["page_cache_state"]=="incremental-warm"
    assert workload_measurement_axes(_workload("watch-filesystem-events"))["output_format"]=="text"


def test_workload_measurement_axes_reject_unmeasured_declared_routes() -> None:
    """WHY: adding a catalog route without a production capture would let release evidence claim coverage that was never measured."""
    workload = replace(
        _workload("filesystem-single-tiny-file"),
        execution_routes=("in-process", "mass-daemon"),
    )
    with pytest.raises(BaselineCaptureError, match="production capture measures only"):
        workload_measurement_axes(workload)


def test_oob_detector_and_command_require_the_real_collector_protocol(tmp_path:pathlib.Path) -> None:
    """WHY: an HTTP-only verification trial can still return live while never registering or polling Interactsh; the generated detector and command must require the callback path explicitly."""
    detector=(prepare_oob_verification_detectors(tmp_path/"detectors")/"github-classic-pat.toml").read_text()
    assert 'url = "https://example.com/verify?callback={{interactsh.url}}"' in detector
    assert '[detector.verify.oob]' in detector and 'policy = "oob_and_http"' in detector
    command=verification_command(_workload("verification-out-of-band"),binary=pathlib.Path("/keyhog"),detectors=tmp_path/"detectors",fixture_root=tmp_path,proxy="http://127.0.0.1:1",output=tmp_path/"out.json",backend="cpu")
    assert command[command.index("--oob-server")+1]=="oast.fun"
    assert command[command.index("--oob-timeout")+1]=="3"
    assert "--verify-oob" in command


def test_default_capture_scope_includes_non_filesystem_families(monkeypatch,tmp_path:pathlib.Path) -> None:
    """WHY: omitting --family previously captured only filesystem while producing a valid-looking artifact; the safe default must include every catalog family."""
    binary=tmp_path/"keyhog"; binary.write_bytes(b"candidate"); calls=[]
    def fake_capture(workload,**kwargs):
        """Test helper / contract verification."""
        calls.append(workload.workload_id); receipt=kwargs["fixture_receipt"]; trials=[_trial(wall,1000+wall,tuple()) for wall in (10,20,30,40,50)]
        return summarize_trials(workload.workload_id,kwargs["backend"],receipt["input_sha256"],receipt["answer_sha256"],sha256_file(binary),trials,tuple(),False)
    monkeypatch.setattr(baseline_capture_module,"capture_slack_baseline",fake_capture)
    payload=capture_baseline_catalog(catalog_path=CATALOG_PATH,fixture_lock_path=LOCK_PATH,fixture_root=tmp_path,target_matrix_path=TARGET_PATH,target_id="linux-x86_64-rtx5090",binary=binary,detectors=tmp_path,backend="cpu",only={"slack-workspace-messages"},host_probe=_test_host_evidence)
    assert calls==["slack-workspace-messages"]
    assert payload["workloads"][0]["workload_id"]=="slack-workspace-messages"


def test_capture_lock_rejects_overlapping_measurements() -> None:
    """WHY: CPU and SIMD captures running together compete for cores, caches, memory bandwidth, and faults, invalidating the wall and RSS baseline while still producing plausible JSON."""
    target="unit-exclusive-target"
    with exclusive_capture_lock(target):
        with pytest.raises(BaselineCaptureError,match="concurrent captures invalidate"):
            with exclusive_capture_lock(target):
                pass
    with exclusive_capture_lock(target):
        pass


def test_startup_profile_preserves_unattributed_process_boundary(tmp_path:pathlib.Path) -> None:
    """WHY: the internal profiler starts after scanner construction, so treating its wall time as process startup hides the runtime compilation cost that the redesign must remove."""
    stats=RunStats(wall_ms=125.0,peak_rss_kb=10,exit_code=0,timed_out=False,minor_page_faults=1,major_page_faults=0)
    row=parse_startup_profile({"wall_time_ns":80_000_000,"stages":[{"stage":"preprocess","elapsed_ns":30_000_000},{"stage":"preprocess","elapsed_ns":5_000_000},{"stage":"backend_select","elapsed_ns":10_000_000}]},stats)
    assert row=={"external_wall_ns":125_000_000,"profile_session_wall_ns":80_000_000,"outside_profile_session_ns":45_000_000,"stages_ns":{"backend_select":10_000_000,"preprocess":35_000_000}}


def test_startup_profile_command_profiles_before_the_scan_root(tmp_path:pathlib.Path) -> None:
    """WHY: a misplaced profile flag can be parsed as a scan root, silently profiling a different workload and invalidating startup attribution."""
    command=startup_profile_command(_workload("filesystem-single-tiny-file"),binary=pathlib.Path("/keyhog"),detectors=tmp_path/"detectors",fixture_root=tmp_path/"fixture",output=tmp_path/"result.json",profile_output=tmp_path/"profile.json",backend="cpu")
    assert command[command.index("--profile-out")+1]==str(tmp_path/"profile.json")
    assert command.index("--profile-out")<command.index(str(tmp_path/"fixture"/"input"))


def test_startup_profile_rejects_malformed_stage_evidence() -> None:
    """WHY: missing stage durations must fail closed instead of being coerced to zero, which would misassign runtime compilation to the process boundary gap."""
    stats=RunStats(wall_ms=1.0,peak_rss_kb=1,exit_code=0,timed_out=False,minor_page_faults=0,major_page_faults=0)
    with pytest.raises(BaselineCaptureError,match=r"stage\[0\] is malformed"):
        parse_startup_profile({"wall_time_ns":1,"stages":[{"stage":"preprocess"}]},stats)


def test_diagnostics_bind_to_one_exact_baseline_generation() -> None:
    """WHY: heap and startup evidence without the catalog, fixture lock, host, target, and binary generation cannot be compared causally to the workload baseline."""
    artifact={"binary_sha256":"a"*64,"backend":"cpu","peak_mapped_bytes":123}
    generation={"binary_sha256":"a"*64,"backend":"cpu","catalog_sha256":"b"*64,"fixture_lock_sha256":"c"*64,"target_matrix_sha256":"d"*64,"target_id":"host","host_evidence":{"cpu":"exact"}}
    bound=bind_diagnostic_provenance(artifact,generation)
    assert bound["target_id"]=="host" and bound["host_evidence"]=={"cpu":"exact"}
    assert "target_id" not in artifact
    generation["binary_sha256"]="e"*64
    with pytest.raises(BaselineCaptureError,match="binary_sha256 differs"):
        bind_diagnostic_provenance(artifact,generation)

def test_installed_pack_commands_omit_custom_detector_override(tmp_path: pathlib.Path) -> None:
    """WHY: passing --detectors bypasses the authenticated installed execution pack and recompiles a custom runtime, invalidating release-candidate memory evidence."""
    filesystem = filesystem_command(
        _workload("filesystem-single-tiny-file"), binary=tmp_path / "keyhog",
        detectors=None, fixture_root=tmp_path / "fixture",
        output=tmp_path / "filesystem.json", backend="cpu",
    )
    stdin = baseline_capture_module.stdin_command(
        _workload("stdin-tiny"), binary=tmp_path / "keyhog", detectors=None,
        output=tmp_path / "stdin.json", backend="cpu",
    )
    concurrency = concurrency_command(
        _workload("concurrency-independent-partitions"), binary=tmp_path / "keyhog",
        detectors=None, partition=tmp_path / "partition-0",
        output=tmp_path / "concurrency.json", backend="simd",
    )
    assert all("--detectors" not in command for command in (filesystem, stdin, concurrency))


def test_execution_pack_capture_binds_manifest_and_scan_metadata(
    monkeypatch, tmp_path: pathlib.Path,
) -> None:
    """WHY: mixed-corpus captures bind each envelope-emitting workload to its exact detector runtime while commands without envelope metadata remain bound to the authenticated manifest generation."""
    binary = tmp_path / "keyhog"
    binary.write_bytes(b"candidate")
    manifest_path = (
        tmp_path / "cache/keyhog/execution-packs/current/manifest.json"
    )
    manifest_path.parent.mkdir(parents=True)
    (manifest_path.parent.parent / "signing.key").write_bytes(b"trusted signing key")
    manifest = {
        "version": 1,
        "detector_digest": "9" * 64,
        "target_digest": "a" * 64,
        "binary_digest": "b" * 64,
        "feature_digest": "c" * 64,
        "fixture_digest": "d" * 64,
        "packs": [{
            "policy": "balanced",
            "backend": "cpu",
            "file": "balanced-cpu.khpack",
            "signature_file": "balanced-cpu.khpack.sig",
            "identity_digest": "e" * 64,
            "content_digest": "f" * 64,
            "signed_pack_digest": "1" * 64,
            "bytes": 1024,
        }],
    }
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    def fake_capture(workload, **kwargs):
        """Test helper / contract verification."""
        assert kwargs["detectors"] is None
        assert baseline_capture_module.os.environ["KEYHOG_REQUIRE_EXECUTION_PACKS"] == "1"
        assert baseline_capture_module.os.environ["XDG_CACHE_HOME"] == str(tmp_path / "cache")
        is_custom = workload.workload_id == "filesystem-mixed-encodings"
        envelope = {
            "metadata": {
                "detector_digest": (
                    "custom-runtime-detector-digest"
                    if is_custom
                    else "925-runtime-detector-digest"
                ),
                "detector_count": 1 if is_custom else 902,
                "resolved_scan": {
                    "effective": {
                        "detector_corpus_digest": ("e" if is_custom else "f") * 64
                    }
                },
            }
        }
        if workload.workload_id != "filesystem-no-extension":
            for _ in range(5):
                baseline_capture_module._observe_execution_pack_metadata(envelope)
        receipt = kwargs["fixture_receipt"]
        trials = [_trial(wall, 1000 + wall, tuple()) for wall in (10, 20, 30, 40, 50)]
        return summarize_trials(
            workload.workload_id, kwargs["backend"], receipt["input_sha256"],
            receipt["answer_sha256"], sha256_file(binary), trials, tuple(), False,
        )

    monkeypatch.setattr(baseline_capture_module, "capture_filesystem_baseline", fake_capture)
    payload = capture_baseline_catalog(
        catalog_path=CATALOG_PATH, fixture_lock_path=LOCK_PATH, fixture_root=tmp_path,
        target_matrix_path=TARGET_PATH, target_id="linux-x86_64-rtx5090",
        binary=binary, backend="cpu", execution_pack_manifest=manifest_path,
        only={
            "filesystem-mixed-encodings",
            "filesystem-no-extension",
            "filesystem-single-tiny-file",
        },
    )
    provenance = payload["runtime_provenance"]
    assert payload["schema_version"] == 4
    assert provenance["manifest_sha256"] == sha256_file(manifest_path)
    assert provenance["candidate_binary_sha256"] == sha256_file(binary)
    assert provenance["workload_detector_provenance"] == {
        "filesystem-mixed-encodings": {
            "mode": "scan-envelope",
            "scan_detector_digest": "custom-runtime-detector-digest",
            "detector_count": 1,
            "detector_corpus_digest": "e" * 64,
        },
        "filesystem-no-extension": {
            "mode": "manifest",
            "execution_pack_detector_digest": "9" * 64,
        },
        "filesystem-single-tiny-file": {
            "mode": "scan-envelope",
            "scan_detector_digest": "925-runtime-detector-digest",
            "detector_count": 902,
            "detector_corpus_digest": "f" * 64,
        },
    }
    validate_baseline_payload(
        payload, catalog_path=CATALOG_PATH, fixture_lock_path=LOCK_PATH,
        target_matrix_path=TARGET_PATH,
        expected_workload_ids={
            "filesystem-mixed-encodings",
            "filesystem-no-extension",
            "filesystem-single-tiny-file",
        },
        binary_path=binary, execution_pack_manifest_path=manifest_path,
    )

    legacy = json.loads(json.dumps(payload))
    legacy["schema_version"] = 3
    legacy["workloads"] = [
        row
        for row in legacy["workloads"]
        if row["workload_id"] == "filesystem-single-tiny-file"
    ]
    legacy_provenance = legacy["runtime_provenance"]
    del legacy_provenance["workload_detector_provenance"]
    legacy_provenance.update({
        "scan_detector_digest": "925-runtime-detector-digest",
        "detector_count": 902,
        "detector_corpus_digest": "f" * 64,
    })
    validate_baseline_payload(
        legacy, catalog_path=CATALOG_PATH, fixture_lock_path=LOCK_PATH,
        target_matrix_path=TARGET_PATH,
        expected_workload_ids={"filesystem-single-tiny-file"},
        binary_path=binary, execution_pack_manifest_path=manifest_path,
    )


def test_execution_pack_capture_rejects_generation_drift(tmp_path: pathlib.Path) -> None:
    """WHY: a manifest or executable replacement during trials would mix distinct installed generations in one benchmark artifact."""
    binary = tmp_path / "keyhog"
    binary.write_bytes(b"candidate")
    manifest_path = tmp_path / "cache/keyhog/execution-packs/current/manifest.json"
    manifest_path.parent.mkdir(parents=True)
    (manifest_path.parent.parent / "signing.key").write_bytes(b"k" * 32)
    manifest = {
        "version": 1,
        "detector_digest": "9" * 64,
        "target_digest": "a" * 64,
        "binary_digest": "b" * 64,
        "feature_digest": "c" * 64,
        "fixture_digest": "d" * 64,
        "packs": [{
            "policy": "balanced",
            "backend": "cpu",
            "file": "balanced-cpu.khpack",
            "signature_file": "balanced-cpu.khpack.sig",
            "identity_digest": "e" * 64,
            "content_digest": "f" * 64,
            "signed_pack_digest": "1" * 64,
            "bytes": 1024,
        }],
    }
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    def drift_manifest(_target):
        """Test helper / contract verification."""
        manifest["fixture_digest"] = "2" * 64
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        return _test_host_evidence(_target)

    with pytest.raises(BaselineCaptureError, match="drifted during capture"):
        capture_baseline_catalog(
            catalog_path=CATALOG_PATH,
            fixture_lock_path=LOCK_PATH,
            fixture_root=tmp_path,
            target_matrix_path=TARGET_PATH,
            target_id="linux-x86_64-rtx5090",
            binary=binary,
            backend="cpu",
            execution_pack_manifest=manifest_path,
            only=set(),
            host_probe=drift_manifest,
        )


def test_capture_requires_one_explicit_detector_mode(tmp_path: pathlib.Path) -> None:
    """WHY: silently inferring installed-pack versus custom-detector mode makes provenance depend on mutable ambient state."""
    binary = tmp_path / "keyhog"
    binary.write_bytes(b"candidate")
    common = {
        "catalog_path": CATALOG_PATH,
        "fixture_lock_path": LOCK_PATH,
        "fixture_root": tmp_path,
        "target_matrix_path": TARGET_PATH,
        "target_id": "linux-x86_64-rtx5090",
        "binary": binary,
        "backend": "cpu",
        "only": set(),
        "host_probe": _test_host_evidence,
    }
    with pytest.raises(BaselineCaptureError, match="select exactly one detector mode"):
        capture_baseline_catalog(**common)
    with pytest.raises(BaselineCaptureError, match="select exactly one detector mode"):
        capture_baseline_catalog(
            **common, detectors=tmp_path,
            execution_pack_manifest=tmp_path / "manifest.json",
        )
def test_validate_baseline_payload_rejects_partial_and_invalid_page_faults(tmp_path: pathlib.Path) -> None:
    """WHY: partial measurements, invalid types, or dangling summary stats fail closed."""
    from bench.baseline_capture import validate_baseline_payload, BaselineCaptureError
    from bench.workload_catalog import load_workload_catalog
    from bench.workload_fixtures import validate_fixture_lock
    catalog = load_workload_catalog(CATALOG_PATH)
    lock = validate_fixture_lock(CATALOG_PATH, LOCK_PATH)
    receipt = lock["workloads"][0]
    wl_id = receipt["workload_id"]

    trials_partial = [
        {"wall_ms": 10, "peak_rss_kb": 100, "minor_page_faults": 5},
        {"wall_ms": 10, "peak_rss_kb": 100, "minor_page_faults": 5},
        {"wall_ms": 10, "peak_rss_kb": 100},
        {"wall_ms": 10, "peak_rss_kb": 100},
        {"wall_ms": 10, "peak_rss_kb": 100},
    ]
    from bench.baseline_capture import BASELINE_SCHEMA_VERSION, sha256_file
    payload = {
        "schema_version": BASELINE_SCHEMA_VERSION,
        "catalog_sha256": sha256_file(CATALOG_PATH),
        "fixture_lock_sha256": sha256_file(LOCK_PATH),
        "target_matrix_sha256": sha256_file(TARGET_PATH),
        "target_id": "linux-x86_64-rtx5090",
        "host_evidence": _test_host_evidence(None),
        "binary_sha256": "a" * 64,
        "backend": "cpu",
        "repetitions": 5,
        "workloads": [
            {
                "workload_id": wl_id,
                "policy": "default",
                "process_state": "cold",
                "page_cache_state": "uncontrolled",
                "output_format": "json-envelope",
                "execution_route": "in-process",
                "fixture_input_sha256": receipt["input_sha256"],
                "fixture_answer_sha256": receipt["answer_sha256"],
                "binary_sha256": "a" * 64,
                "backend": "cpu",
                "p50_wall_ms": 10.0,
                "p95_wall_ms": 10.0,
                "median_peak_rss_kb": 100.0,
                "max_peak_rss_kb": 100,
                "trials": trials_partial,
            }
        ],
    }
    with pytest.raises(BaselineCaptureError, match="partially measured"):
        validate_baseline_payload(payload, catalog_path=CATALOG_PATH, fixture_lock_path=LOCK_PATH, target_matrix_path=TARGET_PATH)
    trials_invalid = [
        {"wall_ms": 10, "peak_rss_kb": 100, "minor_page_faults": -1},
        {"wall_ms": 10, "peak_rss_kb": 100, "minor_page_faults": -1},
        {"wall_ms": 10, "peak_rss_kb": 100, "minor_page_faults": -1},
        {"wall_ms": 10, "peak_rss_kb": 100, "minor_page_faults": -1},
        {"wall_ms": 10, "peak_rss_kb": 100, "minor_page_faults": -1},
    ]
    payload["workloads"][0]["trials"] = trials_invalid
    with pytest.raises(BaselineCaptureError, match="invalid"):
        validate_baseline_payload(payload, catalog_path=CATALOG_PATH, fixture_lock_path=LOCK_PATH, target_matrix_path=TARGET_PATH)
