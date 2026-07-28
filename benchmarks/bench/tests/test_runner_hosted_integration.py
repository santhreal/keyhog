"""Workflow-shaped regressions for hosted CPU evidence production and gating."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone

import pytest

from bench import runner
from bench.corpora.mirror import MirrorCorpus
from bench.hosted_cpu_gate import (
    CONTEXT_SCHEMA,
    HostedCpuInputError,
    TrustedRun,
    capture_context,
    load_policy,
    policy_sha256,
    run_gate,
    write_context,
)
from bench.schema import Host, ScannerConfig, StaticRecoveryMetrics
from bench.scanners.base import MeasurementProvenance, RunStats
from bench.unicode_parity import build_receipt

_COMMIT = "a" * 40
_DETECTOR_SHA = "c" * 64
_REPOSITORY = "santhreal/keyhog"
_WORKFLOW_FILE = ".github/workflows/bench-nightly.yml"
_WORKFLOW_REF = f"{_REPOSITORY}/{_WORKFLOW_FILE}@refs/heads/main"


def _canonical_sha(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _write_mirror(home) -> MirrorCorpus:
    corpus = home / "corpus"
    corpus.mkdir(parents=True)
    records = (
        ("api-found", "api-key", "secret-api-found", "api-found.txt"),
        ("api-missed", "api-key", "secret-api-missed", "api-missed.txt"),
        ("password-found", "password", "secret-password-found", "password.txt"),
    )
    manifest = []
    for record_id, category, secret, relative in records:
        (corpus / relative).write_text(f"{secret}\n", encoding="utf-8")
        manifest.append(
            json.dumps(
                {
                    "id": record_id,
                    "secret": secret,
                    "label": True,
                    "category": category,
                    "on_disk_path": relative,
                    "start_line": 1,
                    "end_line": 1,
                },
                sort_keys=True,
            )
        )
    (home / "manifest.jsonl").write_text("\n".join(manifest) + "\n", encoding="utf-8")
    return MirrorCorpus(corpus_dir=home)


def _scan_manifest() -> dict[str, object]:
    return {
        "schema_version": 1,
        "preset": "full",
        "effective": {"backend": "simd", "confidence_policy": "compiled-default"},
        "overrides": [],
    }


def _write_policy(path, corpus: MirrorCorpus) -> None:
    info = corpus.info()
    row = {
        "id": "mirror-simd-full",
        "path": "results/mirror.json",
        "corpus": "mirror",
        "config": {"backend": "simd", "cache": "off", "daemon": "off", "mode": "full"},
        "min_recall": 0.6,
        "max_wall_ms": 1000.0,
        "min_throughput_mib_s": 0.000001,
        "max_peak_rss_kb": 4096,
        "scan_manifest_sha256": _canonical_sha(_scan_manifest()),
        "categories": [
            {"name": "api-key", "positives": 2, "min_recall": 0.5},
            {"name": "password", "positives": 1, "min_recall": 1.0},
        ],
    }
    raw = {
        "schema_version": "hosted-cpu-policy-v2",
        "authority": {
            "repository": _REPOSITORY,
            "workflow_file": _WORKFLOW_FILE,
            "job": "leaderboard",
            "parity_source_sha256": "d" * 64,
            "parity_vector_sha256": "e" * 64,
            "parity_detector_examples": 3,
        },
        "runner": {
            "profile": "github-ubuntu-24.04-4core-nightly",
            "workflow": "bench-nightly",
            "os": "Linux",
            "arch": "X64",
            "environment": "github-hosted",
            "effective_cores": 4,
            "min_ram_mb": 7000,
            "max_ram_mb": 20000,
            "max_evidence_seconds": 10800,
            "cuda_visible_devices": "",
            "nvidia_visible_devices": "void",
        },
        "supply": {
            "runner_image_version": "20260720.1.0",
            "cpython": "3.12.11",
            "go": "1.22.2",
            "libhyperscan_dev": "5.4.2-2",
            "libhyperscan_runtime": "5.4.2-2",
            "pkg_config": "1.8.1-2build1",
            "libhs_runtime_sha256": "f" * 64,
        },
        "calibration": {
            "status": "unmeasured-release-requirements",
            "thresholds_sha256": _canonical_sha(
                [
                    {
                        field: row[field]
                        for field in (
                            "id",
                            "corpus",
                            "config",
                            "min_recall",
                            "max_wall_ms",
                            "min_throughput_mib_s",
                            "max_peak_rss_kb",
                            "categories",
                        )
                    }
                ]
            ),
            "source": "integration-test acceptance contract",
            "measured_at": None,
            "sample_count": 0,
            "statistic": "none",
            "units": {"wall": "ms", "throughput": "MiB/s", "rss": "KiB", "recall": "ratio"},
            "rationale": "Test-only limits exercise the production evidence contract.",
        },
        "workloads": {
            "mirror": {
                "fixture_count": info.fixture_count,
                "labeled_positives": info.labeled_positives,
                "bytes": info.bytes,
                "workload_sha256": info.workload_sha256,
                "revision": "integration-fixture-v1",
            }
        },
        "rows": [row],
    }
    path.write_text(json.dumps(raw, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _set_first_category_floor(path, value: float) -> None:
    raw = json.loads(path.read_text(encoding="utf-8"))
    raw["rows"][0]["categories"][0]["min_recall"] = value
    raw["calibration"]["thresholds_sha256"] = _canonical_sha(
        [
            {
                field: row[field]
                for field in (
                    "id",
                    "corpus",
                    "config",
                    "min_recall",
                    "max_wall_ms",
                    "min_throughput_mib_s",
                    "max_peak_rss_kb",
                    "categories",
                )
            }
            for row in raw["rows"]
        ]
    )
    path.write_text(json.dumps(raw, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _host() -> Host:
    return Host(
        hostname_hash="012345abcdef",
        os="Linux test",
        kernel="test kernel",
        cpu="GitHub Actions 4-core CPU",
        cores=4,
        affinity_cores=4,
        cgroup_quota_cores=4.0,
        ram_mb=16000,
        gpu="",
        gpu_vram_mb=0,
    )


def _runner_environment() -> dict[str, str]:
    return {
        "GITHUB_ACTIONS": "true",
        "KEYHOG_BENCH_RUNNER_PROFILE": "github-ubuntu-24.04-4core-nightly",
        "RUNNER_NAME": "GitHub Actions integration",
        "RUNNER_OS": "Linux",
        "RUNNER_ARCH": "X64",
        "RUNNER_ENVIRONMENT": "github-hosted",
        "GITHUB_WORKFLOW": "bench-nightly",
        "GITHUB_WORKFLOW_REF": _WORKFLOW_REF,
        "GITHUB_WORKFLOW_SHA": _COMMIT,
        "GITHUB_REPOSITORY": _REPOSITORY,
        "GITHUB_RUN_ID": "1234",
        "GITHUB_RUN_ATTEMPT": "1",
        "GITHUB_JOB": "leaderboard",
        "CUDA_VISIBLE_DEVICES": "",
        "NVIDIA_VISIBLE_DEVICES": "void",
    }


class _WorkflowScanner:
    name = "keyhog"

    def __init__(self, binary):
        self.binary = str(binary)
        self.executable_sha256 = hashlib.sha256(binary.read_bytes()).hexdigest()

    def available(self):
        return True

    def detector_corpus_sha256(self):
        return _DETECTOR_SHA

    def run_with_provenance(self, root, cfg):
        findings = [
            {"file": str(root / "api-found.txt"), "line": 1, "value": "secret-api-found", "detector": "test"},
            {"file": str(root / "password.txt"), "line": 1, "value": "secret-password-found", "detector": "test"},
        ]
        provenance = MeasurementProvenance(
            scanner_version=f"KeyHog integration\nCommit: {_COMMIT}",
            executable_sha256=self.executable_sha256,
            detector_corpus_sha256=_DETECTOR_SHA,
            execution_route="in_process",
            scan_manifest=_scan_manifest(),
            static_recovery=StaticRecoveryMetrics().to_json(),
        )
        return findings, RunStats(wall_ms=100.0, peak_rss_kb=1024, exit_code=1), provenance

    def exit_success(self, code):
        return code in {0, 1, 10}


def test_v2_context_flows_through_runner_scorer_and_gate(tmp_path, monkeypatch):
    """A producer-emitted v2 binding survives scoring, including categories, and passes the real gate."""
    source = _write_mirror(tmp_path / "source-mirror")
    policy_path = tmp_path / "policy.json"
    _write_policy(policy_path, source)
    policy = load_policy(policy_path)
    binary = tmp_path / "keyhog"
    binary.write_bytes(b"integration executable")
    test_executable = tmp_path / "parity-test"
    test_executable.write_bytes(b"parity executable")
    host = _host()
    stamp = datetime.now(timezone.utc).replace(microsecond=0)
    supply_path = tmp_path / "supply.json"
    supply_path.write_text(json.dumps({
        "schema_version": "hosted-cpu-supply-v1",
        "runner_image": {
            "label": "ubuntu-24.04",
            "os": "ubuntu24",
            "version": "20260720.1.0",
        },
        "cpython": {"requested": "3.12.11", "observed": "3.12.11"},
        "go": {"requested": "1.22.2", "observed": "1.22.2"},
        "apt": {
            "libhyperscan-dev": "5.4.2-2",
            "libhyperscan5": "5.4.2-2",
            "pkg-config": "1.8.1-2build1",
        },
        "libhs_runtime": {
            "path": "/usr/lib/x86_64-linux-gnu/libhs.so.5",
            "sha256": "f" * 64,
            "package": "libhyperscan5",
            "package_version": "5.4.2-2",
        },
    }, indent=2, sort_keys=True) + "\n")

    monkeypatch.setenv("KEYHOG_BENCH_MIRROR", str(source.root))
    monkeypatch.setenv("KEYHOG_BENCH_SUPPLY_RECEIPT", str(supply_path))
    monkeypatch.setattr("bench.hosted_cpu_gate.workspace_git_hash", lambda _root: _COMMIT)
    monkeypatch.setattr("bench.hosted_cpu_gate.assert_workspace_tracked_tree_clean", lambda _root: None)
    monkeypatch.setattr("bench.hosted_cpu_gate.workspace_detector_corpus_sha256", lambda _root: _DETECTOR_SHA)
    monkeypatch.setattr("bench.hosted_cpu_gate.capture_host", lambda: host)
    monkeypatch.setattr(
        "bench.hosted_cpu_gate.capture_accelerator_inventory",
        lambda: {
            "source": "nvidia-smi",
            "status": "nvidia-smi-unavailable",
            "devices": [],
        },
    )
    monkeypatch.setattr(runner.hardware, "capture", lambda: host)

    context = capture_context(
        policy_path,
        _COMMIT,
        binary,
        ["mirror"],
        repo_root=tmp_path,
        snapshot_root=tmp_path / "snapshot",
        environ={**_runner_environment(), "KEYHOG_BENCH_SUPPLY_RECEIPT": str(supply_path)},
        generated_at=stamp.isoformat(),
    )
    context["immutability"] = {
        "schema_version": "hosted-cpu-immutability-v1",
        "snapshot_root": str((tmp_path / "snapshot").resolve()),
        "owner": "root:root",
        "mount_options": ["bind", "ro"],
        "write_probe": "rejected",
        "interval_end": "post-publication cleanup",
    }
    assert context["schema_version"] == CONTEXT_SCHEMA
    context_path = tmp_path / "context.json"
    write_context(context, context_path)
    context_raw = context_path.read_bytes()
    context_sha = hashlib.sha256(context_raw).hexdigest()
    monkeypatch.setenv("KEYHOG_BENCH_HOSTED_CONTEXT", str(context_path))

    snapshot_corpus = MirrorCorpus(corpus_dir=context["snapshot_roots"]["mirror"])
    result = runner._run_resolved_scanner(
        _WorkflowScanner(binary),
        "unbound pre-scan version",
        ScannerConfig(backend="simd", cache="off", daemon="off", mode="full"),
        snapshot_corpus,
    )

    assert result.available is True, result.error
    assert result.hosted_binding is not None
    assert result.hosted_binding.context_sha256 == context_sha
    assert result.detection.overall.tp == 2
    assert result.detection.overall.fn == 1
    assert result.detection.per_category["api-key"].tp == 1
    assert result.detection.per_category["api-key"].fn == 1
    assert result.detection.per_category["password"].tp == 1
    assert result.detection.per_category["password"].fn == 0

    result_path = tmp_path / "results" / "mirror.json"
    runner.write_result(result, result_path)
    parity = build_receipt(
        context,
        "backend parity: 3 detector examples; CPU == SIMD on all ASCII inputs; 0 unicode-input divergences",
        expected_examples=3,
        context_sha256=context_sha,
        release_executable_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
        test_executable_sha256=hashlib.sha256(test_executable.read_bytes()).hexdigest(),
        parity_source_sha256=policy.parity_source_sha256,
        vector_sha256=policy.parity_vector_sha256,
        command=[str(test_executable), "--nocapture"],
        generated_at=stamp.isoformat(),
    )
    parity_path = tmp_path / "parity.json"
    parity_path.write_text(json.dumps(parity, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    trusted = TrustedRun(
        now=datetime.now(timezone.utc),
        policy_sha256=policy_sha256(policy_path),
        repository=_REPOSITORY,
        workflow_ref=_WORKFLOW_REF,
        workflow_sha=_COMMIT,
        run_id="1234",
        run_attempt="1",
        job="leaderboard",
    )

    assert run_gate(policy_path, context_path, parity_path, tmp_path, trusted=trusted) == 0


def test_category_recall_floor_accepts_explicit_zero(tmp_path):
    """A preset can truthfully declare no recall guarantee for an unsupported category."""
    source = _write_mirror(tmp_path / "source-mirror")
    policy_path = tmp_path / "policy.json"
    _write_policy(policy_path, source)
    _set_first_category_floor(policy_path, 0.0)

    policy = load_policy(policy_path)
    assert policy.rows[0].categories[0].min_recall == 0.0


@pytest.mark.parametrize("invalid_floor", [-0.0001, 1.0001])
def test_category_recall_floor_rejects_values_outside_closed_ratio(tmp_path, invalid_floor):
    """Zero is explicit, but negative and above-one recall floors remain invalid."""
    source = _write_mirror(tmp_path / "source-mirror")
    policy_path = tmp_path / "policy.json"
    _write_policy(policy_path, source)
    _set_first_category_floor(policy_path, invalid_floor)

    with pytest.raises(HostedCpuInputError, match=r"must be in \[0, 1\]"):
        load_policy(policy_path)