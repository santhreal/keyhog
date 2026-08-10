"""End-to-end wall and peak-RSS baseline capture over canonical fixtures."""

from __future__ import annotations

import argparse
import base64
import concurrent.futures
import contextlib
import hashlib
import http.server
import json
import math
import os
import pathlib
import platform
import signal
import socketserver
import ssl
import subprocess
import statistics
import tempfile
import tarfile
import threading
import urllib.parse
import time
from dataclasses import dataclass
from typing import Callable, Sequence

from .keyhog_daemon import OwnedKeyhogDaemon
from .scanners.base import RunStats, run_measured
from .target_matrix import TargetIdentity, load_target_matrix, target_matrix_sha256
from .workload_catalog import Workload, load_workload_catalog
from .workload_fixtures import validate_fixture_lock

BASELINE_SCHEMA_VERSION = 2
SUCCESS_EXIT_CODES = frozenset({0, 1, 10, 13})
MIN_TRIALS = 5
LEGACY_PACK_BASELINE_SCHEMA_VERSION = 3
PACK_BASELINE_SCHEMA_VERSION = 4
_PACK_MANIFEST_FIELDS = {
    "version", "detector_digest", "target_digest", "binary_digest",
    "feature_digest", "fixture_digest", "packs",
}
_PACK_MANIFEST_ENTRY_FIELDS = {
    "policy", "backend", "file", "signature_file", "identity_digest",
    "content_digest", "signed_pack_digest", "bytes",
}
_active_pack_observations: list[tuple[str, int, str]] | None = None


class BaselineCaptureError(RuntimeError):
    """A baseline run that failed provenance, execution, or result validation."""


@dataclass(frozen=True)
class BaselineTrial:
    """One complete process execution over an exact fixture."""

    wall_ms: float
    peak_rss_kb: int
    minor_page_faults: int | None
    major_page_faults: int | None
    exit_code: int
    finding_count: int
    finding_hashes: tuple[str, ...]
    coverage_gap_count: int
    result_error: str

    def to_json(self) -> dict[str, object]:
        """Serialize run metrics to a JSON-serializable dictionary."""
        return {
            "wall_ms": self.wall_ms,
            "peak_rss_kb": self.peak_rss_kb,
            "minor_page_faults": self.minor_page_faults,
            "major_page_faults": self.major_page_faults,
            "exit_code": self.exit_code,
            "finding_count": self.finding_count,
            "finding_hashes": list(self.finding_hashes),
            "coverage_gap_count": self.coverage_gap_count,
            "result_error": self.result_error,
        }


@dataclass(frozen=True)
class BaselineSummary:
    """Robust current-state timing and memory baseline for one workload route."""

    workload_id: str
    backend: str
    fixture_input_sha256: str
    fixture_answer_sha256: str
    binary_sha256: str
    trials: tuple[BaselineTrial, ...]
    p50_wall_ms: float
    p95_wall_ms: float
    median_peak_rss_kb: float
    max_peak_rss_kb: int
    p50_minor_page_faults: float | None
    p95_minor_page_faults: float | None
    p50_major_page_faults: float | None
    p95_major_page_faults: float | None
    parity_ok: bool

    def to_json(self) -> dict[str, object]:
        """Serialize baseline summary statistics to a JSON-serializable dictionary."""
        return {
            "schema_version": BASELINE_SCHEMA_VERSION,
            "workload_id": self.workload_id,
            "backend": self.backend,
            "fixture_input_sha256": self.fixture_input_sha256,
            "fixture_answer_sha256": self.fixture_answer_sha256,
            "binary_sha256": self.binary_sha256,
            "trials": [trial.to_json() for trial in self.trials],
            "p50_wall_ms": self.p50_wall_ms,
            "p95_wall_ms": self.p95_wall_ms,
            "median_peak_rss_kb": self.median_peak_rss_kb,
            "max_peak_rss_kb": self.max_peak_rss_kb,
            "p50_minor_page_faults": self.p50_minor_page_faults,
            "p95_minor_page_faults": self.p95_minor_page_faults,
            "p50_major_page_faults": self.p50_major_page_faults,
            "p95_major_page_faults": self.p95_major_page_faults,
            "parity_ok": self.parity_ok,
        }


TrialRunner = Callable[[Sequence[str]], tuple[str, str, RunStats]]



def capture_target_evidence(target: TargetIdentity) -> dict[str, object]:
    """Prove the current host matches one exact pinned target before timing it."""
    observed_os = platform.system().lower()
    observed_arch = platform.machine().lower()
    if observed_arch == "amd64":
        observed_arch = "x86_64"
    if target.identity_mode != "exact":
        raise BaselineCaptureError(
            f"automatic host evidence requires an exact target, got {target.identity_mode!r}"
        )
    if observed_os != target.os or observed_arch != target.arch:
        raise BaselineCaptureError(
            f"host platform {observed_os}/{observed_arch} does not match "
            f"{target.os}/{target.arch}"
        )
    cpu = ""
    for line in pathlib.Path("/proc/cpuinfo").read_text(encoding="utf-8").splitlines():
        if line.startswith("model name"):
            cpu = line.split(":", 1)[1].strip()
            break
    logical_cores = os.cpu_count() or 0
    mem_line = next(
        line for line in pathlib.Path("/proc/meminfo").read_text(encoding="utf-8").splitlines()
        if line.startswith("MemTotal:")
    )
    ram_mb = int(mem_line.split()[1]) // 1024
    if cpu != target.cpu or logical_cores != target.logical_cores or ram_mb < target.min_ram_mb:
        raise BaselineCaptureError(
            f"host CPU/RAM identity differs: cpu={cpu!r}, cores={logical_cores}, ram_mb={ram_mb}"
        )
    completed = subprocess.run(
        [
            "nvidia-smi", "--query-gpu=name,memory.total,driver_version",
            "--format=csv,noheader,nounits",
        ],
        capture_output=True, text=True, check=False, timeout=10,
    )
    if completed.returncode != 0:
        raise BaselineCaptureError(f"nvidia-smi could not prove GPU identity: {completed.stderr.strip()}")
    gpu_line = completed.stdout.splitlines()[0]
    gpu, memory_text, driver = (part.strip() for part in gpu_line.split(",", 2))
    gpu_vram_mb = int(memory_text)
    if gpu != target.gpu or driver != target.gpu_driver or gpu_vram_mb < target.min_gpu_vram_mb:
        raise BaselineCaptureError(
            f"host GPU identity differs: gpu={gpu!r}, vram_mb={gpu_vram_mb}, driver={driver!r}"
        )
    return {
        "os": observed_os, "arch": observed_arch, "cpu": cpu,
        "logical_cores": logical_cores, "ram_mb": ram_mb, "gpu": gpu,
        "gpu_vram_mb": gpu_vram_mb, "gpu_driver": driver,
        "kernel": platform.release(),
    }

def percentile_nearest_rank(values: Sequence[float], percentile: float) -> float:
    """Return the deterministic nearest-rank percentile of finite samples."""
    if not values:
        raise BaselineCaptureError("percentile requires at least one sample")
    if not 0.0 < percentile <= 1.0:
        raise BaselineCaptureError(f"percentile must be in (0, 1], got {percentile}")
    finite = [float(value) for value in values]
    if any(not math.isfinite(value) for value in finite):
        raise BaselineCaptureError("percentile samples must be finite")
    ordered = sorted(finite)
    index = max(0, math.ceil(len(ordered) * percentile) - 1)
    return ordered[index]


def sha256_file(path: str | pathlib.Path) -> str:
    """Hash one exact executable without loading it all into memory."""
    hasher = hashlib.sha256()
    with pathlib.Path(path).open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            hasher.update(chunk)
    return hasher.hexdigest()
def _detector_args(detectors: pathlib.Path | None) -> list[str]:
    """Format CLI detector flags for executable invocation."""
    return [] if detectors is None else ["--detectors", str(detectors)]


def _resolve_detectors(detectors: str | pathlib.Path | None) -> pathlib.Path | None:
    """Resolve strict path for detector rules file if supplied."""
    return None if detectors is None else pathlib.Path(detectors).resolve(strict=True)


def _load_execution_pack_manifest(
    path: str | pathlib.Path, binary: pathlib.Path,
) -> tuple[pathlib.Path, dict[str, object]]:
    """Load and validate execution pack manifest JSON against expected path structure."""
    manifest_path = pathlib.Path(path).resolve(strict=True)
    if (
        manifest_path.name != "manifest.json"
        or manifest_path.parent.name != "current"
        or manifest_path.parent.parent.name != "execution-packs"
        or manifest_path.parent.parent.parent.name != "keyhog"
    ):
        raise BaselineCaptureError(
            "execution-pack manifest must be <XDG_CACHE_HOME>/keyhog/"
            "execution-packs/current/manifest.json"
        )
    signing_key = manifest_path.parent.parent / "signing.key"
    if not signing_key.is_file():
        raise BaselineCaptureError(f"execution-pack signing key is missing: {signing_key}")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BaselineCaptureError(f"cannot load execution-pack manifest: {exc}") from exc
    if not isinstance(manifest, dict) or set(manifest) != _PACK_MANIFEST_FIELDS:
        observed = sorted(manifest) if isinstance(manifest, dict) else type(manifest).__name__
        raise BaselineCaptureError(
            f"execution-pack manifest fields differ: expected={sorted(_PACK_MANIFEST_FIELDS)}, "
            f"observed={observed}"
        )
    digest_fields = _PACK_MANIFEST_FIELDS - {"version", "packs"}
    for field in digest_fields:
        value = manifest[field]
        if (
            not isinstance(value, str)
            or len(value) != 64
            or any(character not in "0123456789abcdef" for character in value)
        ):
            raise BaselineCaptureError(
                f"execution-pack manifest {field} is not a lowercase 32-byte digest"
            )
    if manifest["version"] != 1:
        raise BaselineCaptureError(
            f"execution-pack manifest version {manifest['version']!r} is unsupported"
        )
    packs = manifest["packs"]
    if not isinstance(packs, list) or not packs:
        raise BaselineCaptureError("execution-pack manifest packs are missing")
    for index, pack in enumerate(packs):
        if not isinstance(pack, dict) or set(pack) != _PACK_MANIFEST_ENTRY_FIELDS:
            raise BaselineCaptureError(
                f"execution-pack manifest pack[{index}] fields differ"
            )
        for field in ("policy", "backend", "file", "signature_file"):
            if not isinstance(pack[field], str) or not pack[field]:
                raise BaselineCaptureError(
                    f"execution-pack manifest pack[{index}] {field} is missing"
                )
        for field in ("identity_digest", "content_digest", "signed_pack_digest"):
            value = pack[field]
            if (
                not isinstance(value, str)
                or len(value) != 64
                or any(character not in "0123456789abcdef" for character in value)
            ):
                raise BaselineCaptureError(
                    f"execution-pack manifest pack[{index}] {field} is malformed"
                )
        if (
            isinstance(pack["bytes"], bool)
            or not isinstance(pack["bytes"], int)
            or pack["bytes"] <= 0
        ):
            raise BaselineCaptureError(
                f"execution-pack manifest pack[{index}] bytes is malformed"
            )
    return manifest_path, {
        "mode": "installed-execution-pack",
        "manifest_sha256": sha256_file(manifest_path),
        "signing_key_sha256": sha256_file(signing_key),
        "candidate_binary_sha256": sha256_file(binary),
        **manifest,
    }


@contextlib.contextmanager
def _execution_pack_capture(manifest_path: pathlib.Path | None):
    """Benchmark fixture component or validation handler."""
    global _active_pack_observations
    if manifest_path is None:
        yield None
        return
    if _active_pack_observations is not None:
        raise BaselineCaptureError("nested execution-pack captures are not supported")
    previous = {
        name: os.environ.get(name)
        for name in ("KEYHOG_REQUIRE_EXECUTION_PACKS", "XDG_CACHE_HOME")
    }
    _active_pack_observations = []
    os.environ["KEYHOG_REQUIRE_EXECUTION_PACKS"] = "1"
    os.environ["XDG_CACHE_HOME"] = str(manifest_path.parents[3])
    try:
        yield _active_pack_observations
    finally:
        _active_pack_observations = None
        for name, value in previous.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


def _observe_execution_pack_metadata(envelope: dict[str, object]) -> None:
    """Benchmark fixture component or validation handler."""
    if _active_pack_observations is None:
        return
    metadata = envelope.get("metadata")
    resolved = metadata.get("resolved_scan") if isinstance(metadata, dict) else None
    effective = resolved.get("effective") if isinstance(resolved, dict) else None
    detector_digest = metadata.get("detector_digest") if isinstance(metadata, dict) else None
    detector_count = metadata.get("detector_count") if isinstance(metadata, dict) else None
    corpus_digest = (
        effective.get("detector_corpus_digest") if isinstance(effective, dict) else None
    )
    if (
        not isinstance(detector_digest, str) or not detector_digest
        or isinstance(detector_count, bool) or not isinstance(detector_count, int)
        or detector_count <= 0
        or not isinstance(corpus_digest, str) or not corpus_digest
    ):
        raise BaselineCaptureError("scan envelope lacks execution-pack detector provenance")
    _active_pack_observations.append((detector_digest, detector_count, corpus_digest))


def _filesystem_scan_roots(workload: Workload, fixture_root: pathlib.Path) -> list[str]:
    """Benchmark fixture component or validation handler."""
    input_root = fixture_root / "input"
    if workload.workload_id == "filesystem-multiple-roots":
        return [str(input_root / f"root-{index}") for index in range(3)]
    if workload.workload_id in {
        "filesystem-binary-strings",
        "filesystem-binary-decompiler",
    }:
        return [str(input_root / "program.bin")]
    return [str(input_root)]


def filesystem_command(
    workload: Workload,
    *,
    binary: pathlib.Path,
    detectors: pathlib.Path | None,
    fixture_root: pathlib.Path,
    output: pathlib.Path,
    backend: str,
) -> list[str]:
    """Build the exact in-process command for one canonical filesystem workload."""
    if workload.family != "filesystem":
        raise BaselineCaptureError(
            f"filesystem driver cannot execute workload family {workload.family!r}"
        )
    command = [
        str(binary),
        "scan",
        "--no-config",
        *_detector_args(detectors),
        "--backend",
        backend,
        "--daemon=off",
        "--format",
        "json-envelope",
        "--show-secrets",
        "--no-default-excludes",
        "--no-suppress-test-fixtures",
        "--dedup",
        "file",
        "--quiet",
        "--output",
        str(output),
    ]
    if backend in {"cpu", "simd"}:
        command.append("--no-gpu")
    if workload.workload_id == "filesystem-single-large-file":
        command.extend(["--max-file-size", "512M"])
    if workload.workload_id in {
        "filesystem-binary-strings",
        "filesystem-binary-decompiler",
    }:
        command.append("--binary")
    command.extend(_filesystem_scan_roots(workload, fixture_root))
    return command



@contextlib.contextmanager
def runtime_fixture_state(fixture_root: pathlib.Path):
    """Apply and then restore canonical permission and mutation-time fixture state."""
    input_root = fixture_root / "input"
    unreadable_plan = input_root / "unreadable-plan.json"
    restored_modes: list[tuple[pathlib.Path, int]] = []
    if unreadable_plan.is_file():
        plan = json.loads(unreadable_plan.read_text(encoding="utf-8"))
        for relative in reversed(plan["paths"]):
            target = input_root / relative
            restored_modes.append((target, target.stat().st_mode & 0o7777))
            target.chmod(int(plan["mode"]))

    mutation_plan = input_root / "changing/mutator.json"
    stop = threading.Event()
    worker: threading.Thread | None = None
    originals: dict[pathlib.Path, bytes] = {}
    if mutation_plan.is_file():
        plan = json.loads(mutation_plan.read_text(encoding="utf-8"))
        base = mutation_plan.parent
        growing = base / plan["append"]
        shrinking = base / plan["truncate"]
        originals = {growing: growing.read_bytes(), shrinking: shrinking.read_bytes()}

        def mutate() -> None:
            """Background thread worker to continuously mutate growing and shrinking files."""
            while not stop.is_set():
                with growing.open("ab") as handle:
                    handle.write(b"runtime append\n")
                with shrinking.open("r+b") as handle:
                    handle.truncate(max(len(b"GITHUB_TOKEN="), shrinking.stat().st_size // 2))
                time.sleep(0.001)

        worker = threading.Thread(target=mutate, name="fixture-size-mutator", daemon=True)
        worker.start()
    try:
        yield
    finally:
        stop.set()
        if worker is not None:
            worker.join(timeout=5)
        for path, data in originals.items():
            path.write_bytes(data)
        for path, mode in reversed(restored_modes):
            path.chmod(mode)

def _parse_trial(output: pathlib.Path, stats: RunStats) -> BaselineTrial:
    """Benchmark fixture component or validation handler."""
    if stats.timed_out or stats.exit_code not in SUCCESS_EXIT_CODES:
        raise BaselineCaptureError(
            f"baseline command exited {stats.exit_code}, timed_out={stats.timed_out}"
        )
    try:
        envelope = json.loads(output.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return BaselineTrial(
            wall_ms=stats.wall_ms,
            peak_rss_kb=stats.peak_rss_kb,
            minor_page_faults=stats.minor_page_faults,
            major_page_faults=stats.major_page_faults,
            exit_code=stats.exit_code,
            finding_count=0,
            finding_hashes=tuple(),
            coverage_gap_count=0,
            result_error=f"no valid envelope: {type(exc).__name__}: {exc}",
        )
    findings = envelope.get("findings")
    gaps = envelope.get("coverage_gap_summary")
    if not isinstance(findings, list) or not isinstance(gaps, list):
        raise BaselineCaptureError("baseline envelope lacks findings or coverage gaps")
    _observe_execution_pack_metadata(envelope)
    hashes: list[str] = []
    for index, finding in enumerate(findings):
        if not isinstance(finding, dict):
            raise BaselineCaptureError(f"finding[{index}] is not an object")
        digest = finding.get("credential_hash")
        if not isinstance(digest, str) or len(digest) != 64:
            raise BaselineCaptureError(f"finding[{index}] has no SHA-256 credential hash")
        hashes.append(digest)
    return BaselineTrial(
        wall_ms=stats.wall_ms,
        peak_rss_kb=stats.peak_rss_kb,
        minor_page_faults=stats.minor_page_faults,
        major_page_faults=stats.major_page_faults,
        exit_code=stats.exit_code,
        finding_count=len(findings),
        finding_hashes=tuple(sorted(hashes)),
        coverage_gap_count=len(gaps),
        result_error="",
    )


def _fixture_expectation(fixture_root: pathlib.Path) -> tuple[tuple[str, ...], bool]:
    """Benchmark fixture component or validation handler."""
    receipt = json.loads((fixture_root / "fixture.json").read_text(encoding="utf-8"))
    answers = json.loads((fixture_root / "answers.json").read_text(encoding="utf-8"))
    expected_hashes = tuple(sorted(answer["credential_sha256"] for answer in answers))
    return expected_hashes, bool(receipt["expected_coverage_gap"])


def summarize_trials(
    workload_id: str,
    backend: str,
    fixture_input_sha256: str,
    fixture_answer_sha256: str,
    binary_sha256: str,
    trials: Sequence[BaselineTrial],
    expected_hashes: tuple[str, ...],
    expected_gap: bool,
) -> BaselineSummary:
    """Build exact p50, p95, RSS, and parity evidence from complete trials."""
    if len(trials) < MIN_TRIALS:
        raise BaselineCaptureError(
            f"baseline requires at least {MIN_TRIALS} trials, got {len(trials)}"
        )
    walls = [trial.wall_ms for trial in trials]
    rss = [trial.peak_rss_kb for trial in trials]
    minor_faults = [trial.minor_page_faults for trial in trials]
    major_faults = [trial.major_page_faults for trial in trials]
    measured_minor = [value for value in minor_faults if value is not None]
    measured_major = [value for value in major_faults if value is not None]
    parity_ok = all(
        not trial.result_error
        and trial.finding_hashes == expected_hashes
        and ((trial.coverage_gap_count > 0) == expected_gap)
        for trial in trials
    )
    return BaselineSummary(
        workload_id=workload_id,
        backend=backend,
        fixture_input_sha256=fixture_input_sha256,
        fixture_answer_sha256=fixture_answer_sha256,
        binary_sha256=binary_sha256,
        trials=tuple(trials),
        p50_wall_ms=statistics.median(walls),
        p95_wall_ms=percentile_nearest_rank(walls, 0.95),
        median_peak_rss_kb=statistics.median(rss),
        max_peak_rss_kb=max(rss),
        p50_minor_page_faults=(statistics.median(measured_minor) if len(measured_minor) == len(trials) else None),
        p95_minor_page_faults=(percentile_nearest_rank(measured_minor, 0.95) if len(measured_minor) == len(trials) else None),
        p50_major_page_faults=(statistics.median(measured_major) if len(measured_major) == len(trials) else None),
        p95_major_page_faults=(percentile_nearest_rank(measured_major, 0.95) if len(measured_major) == len(trials) else None),
        parity_ok=parity_ok,
    )



def stdin_command(
    workload: Workload,
    *,
    binary: pathlib.Path,
    detectors: pathlib.Path | None,
    output: pathlib.Path,
    backend: str,
) -> list[str]:
    """Build one explicit-backend stdin command for a canonical workload."""
    if workload.family != "stdin":
        raise BaselineCaptureError(f"{workload.workload_id} is not a stdin workload")
    if backend not in {"cpu", "simd"}:
        raise BaselineCaptureError(f"unsupported CPU baseline backend: {backend}")
    return [
        str(binary), "scan", "--no-config", "--stdin", *_detector_args(detectors),
        "--backend", backend, "--no-gpu", "--daemon=off", "--format",
        "json-envelope", "--show-secrets", "--no-default-excludes",
        "--no-suppress-test-fixtures", "--dedup", "file", "--quiet",
        "--output", str(output),
    ]


def capture_stdin_baseline(
    workload: Workload,
    *,
    binary: str | pathlib.Path,
    detectors: str | pathlib.Path | None,
    fixture_root: str | pathlib.Path,
    fixture_receipt: dict[str, object],
    backend: str,
    repetitions: int = MIN_TRIALS,
    runner: Callable[[Sequence[str], pathlib.Path], tuple[str, str, RunStats]] | None = None,
) -> BaselineSummary:
    """Measure whole-process stdin ingestion and verify its exact answer multiset."""
    fixture_path = pathlib.Path(fixture_root)
    stdin_path = fixture_path / "input/stdin.bin"
    expected_hashes, expected_coverage_gap = _fixture_expectation(fixture_path)
    binary_path = pathlib.Path(binary)
    if runner is None:
        runner = lambda command, source: run_measured(command, stdin_path=source)
    trials: list[BaselineTrial] = []
    with tempfile.TemporaryDirectory(prefix=f"keyhog-baseline-{workload.workload_id}-") as temp:
        temp_root = pathlib.Path(temp)
        for repetition in range(repetitions):
            output = temp_root / f"trial-{repetition}.json"
            command = stdin_command(
                workload, binary=binary_path, detectors=_resolve_detectors(detectors),
                output=output, backend=backend,
            )
            _stdout, _stderr, stats = runner(command, stdin_path)
            trials.append(_parse_trial(output, stats))
    return summarize_trials(
        workload.workload_id, backend, str(fixture_receipt["input_sha256"]),
        str(fixture_receipt["answer_sha256"]), sha256_file(binary_path), trials,
        expected_hashes, expected_coverage_gap,
    )


def _git_run(repository: pathlib.Path, *args: str) -> None:
    """Benchmark fixture component or validation handler."""
    env = dict(os.environ)
    env.update({
        "GIT_AUTHOR_NAME": "KeyHog Benchmark", "GIT_AUTHOR_EMAIL": "benchmark@invalid",
        "GIT_COMMITTER_NAME": "KeyHog Benchmark", "GIT_COMMITTER_EMAIL": "benchmark@invalid",
        "GIT_AUTHOR_DATE": "2000-01-01T00:00:00Z",
        "GIT_COMMITTER_DATE": "2000-01-01T00:00:00Z",
    })
    completed = subprocess.run(
        ["git", "-C", str(repository), *args], capture_output=True, text=True,
        check=False, env=env, timeout=30,
    )
    if completed.returncode != 0:
        raise BaselineCaptureError(
            f"git fixture command failed: {completed.stderr.strip()}"
        )


def prepare_git_repository(
    workload: Workload, fixture_root: pathlib.Path, destination: pathlib.Path
) -> pathlib.Path:
    """Build one deterministic repository state outside the timed child process."""
    if workload.family != "git":
        raise BaselineCaptureError(f"{workload.workload_id} is not a git workload")
    repository = destination / "repository"
    repository.mkdir(parents=True)
    _git_run(repository, "init", "--quiet", "--initial-branch=main")
    (repository / "clean.txt").write_text("clean baseline\n", encoding="utf-8")
    _git_run(repository, "add", "clean.txt")
    _git_run(repository, "commit", "--quiet", "-m", "base")
    secret = (fixture_root / "input/repository/secret.env").read_bytes()
    secret_path = repository / "secret.env"
    secret_path.write_bytes(secret)
    workload_id = workload.workload_id
    if workload_id == "git-staged-index":
        _git_run(repository, "add", "secret.env")
    elif workload_id == "git-diff-lines":
        _git_run(repository, "add", "secret.env")
    elif workload_id in {"git-reachable-blobs", "git-shallow-clone"}:
        _git_run(repository, "add", "secret.env")
        _git_run(repository, "commit", "--quiet", "-m", "add secret")
    elif workload_id == "git-commit-history":
        _git_run(repository, "add", "secret.env")
        _git_run(repository, "commit", "--quiet", "-m", "add secret")
        secret_path.unlink()
        _git_run(repository, "add", "-u")
        _git_run(repository, "commit", "--quiet", "-m", "remove secret")
    else:
        raise BaselineCaptureError(f"unsupported git workload {workload_id!r}")
    if workload_id == "git-shallow-clone":
        shallow = destination / "shallow"
        completed = subprocess.run(
            ["git", "clone", "--quiet", "--depth", "1", repository.as_uri(), str(shallow)],
            capture_output=True, text=True, check=False, timeout=30,
        )
        if completed.returncode != 0:
            raise BaselineCaptureError(f"shallow clone fixture failed: {completed.stderr.strip()}")
        return shallow
    return repository


def git_command(
    workload: Workload, *, binary: pathlib.Path, detectors: pathlib.Path,
    repository: pathlib.Path, output: pathlib.Path, backend: str,
) -> list[str]:
    """Build one explicit-backend command for a prepared Git repository."""
    command = [
        str(binary), "scan", "--no-config", *_detector_args(detectors),
        "--backend", backend, "--no-gpu", "--daemon=off", "--format",
        "json-envelope", "--show-secrets", "--no-suppress-test-fixtures",
        "--dedup", "file", "--quiet", "--output", str(output),
    ]
    if workload.workload_id == "git-staged-index":
        command.extend(["--git-staged", str(repository)])
    elif workload.workload_id == "git-diff-lines":
        command.extend(["--git-diff", "HEAD", "--git-diff-path", str(repository)])
    elif workload.workload_id == "git-reachable-blobs":
        command.extend(["--git-blobs", str(repository)])
    else:
        command.extend(["--git-history", str(repository)])
    return command


def capture_git_baseline(
    workload: Workload, *, binary: str | pathlib.Path, detectors: str | pathlib.Path,
    fixture_root: str | pathlib.Path, fixture_receipt: dict[str, object],
    backend: str, repetitions: int = MIN_TRIALS, runner: TrialRunner = lambda command: run_measured(list(command)),
) -> BaselineSummary:
    """Measure whole-process Git acquisition over a deterministic repository state."""
    if repetitions < MIN_TRIALS:
        raise BaselineCaptureError(
            f"baseline repetitions must be at least {MIN_TRIALS}, got {repetitions}"
        )
    binary_path = pathlib.Path(binary).resolve(strict=True)
    detector_path = _resolve_detectors(detectors)
    fixture_path = pathlib.Path(fixture_root).resolve(strict=True)
    expected_hashes, expected_gap = _fixture_expectation(fixture_path)
    trials: list[BaselineTrial] = []
    with tempfile.TemporaryDirectory(prefix=f"keyhog-git-{workload.workload_id}-") as raw:
        temp_root = pathlib.Path(raw)
        repository = prepare_git_repository(workload, fixture_path, temp_root)
        for index in range(repetitions):
            output = temp_root / f"trial-{index}.json"
            command = git_command(
                workload, binary=binary_path, detectors=detector_path,
                repository=repository, output=output, backend=backend,
            )
            _stdout, _stderr, stats = runner(command)
            trials.append(_parse_trial(output, stats))
    return summarize_trials(
        workload.workload_id, backend, str(fixture_receipt["input_sha256"]),
        str(fixture_receipt["answer_sha256"]), sha256_file(binary_path), trials,
        expected_hashes, expected_gap,
    )


def incremental_command(
    workload: Workload, *, binary: pathlib.Path, detectors: pathlib.Path,
    fixture_root: pathlib.Path, cache_path: pathlib.Path, output: pathlib.Path,
    backend: str,
) -> list[str]:
    """Build one explicit-cache incremental scan command."""
    if workload.family != "incremental":
        raise BaselineCaptureError(f"{workload.workload_id} is not incremental")
    return [
        str(binary), "scan", "--no-config", *_detector_args(detectors),
        "--backend", backend, "--no-gpu", "--daemon=off", "--incremental",
        "--incremental-cache", str(cache_path), "--format", "json-envelope",
        "--show-secrets", "--no-default-excludes", "--no-suppress-test-fixtures",
        "--dedup", "file", "--quiet", "--output", str(output),
        str(fixture_root / "input/tree"),
    ]


def capture_incremental_baseline(
    workload: Workload, *, binary: str | pathlib.Path, detectors: str | pathlib.Path,
    fixture_root: str | pathlib.Path, fixture_receipt: dict[str, object],
    backend: str, repetitions: int = MIN_TRIALS, runner: TrialRunner = lambda command: run_measured(list(command)),
) -> BaselineSummary:
    """Measure cold-index creation or steady warm-index lookup as declared."""
    if repetitions < MIN_TRIALS:
        raise BaselineCaptureError(
            f"baseline repetitions must be at least {MIN_TRIALS}, got {repetitions}"
        )
    binary_path = pathlib.Path(binary).resolve(strict=True)
    detector_path = _resolve_detectors(detectors)
    fixture_path = pathlib.Path(fixture_root).resolve(strict=True)
    expected_hashes, expected_gap = _fixture_expectation(fixture_path)
    trials: list[BaselineTrial] = []
    with tempfile.TemporaryDirectory(prefix=f"keyhog-incremental-{workload.workload_id}-") as raw:
        temp_root = pathlib.Path(raw)
        cache_path = temp_root / "cache/index.json"
        if workload.workload_id == "incremental-warm-index":
            cache_path.parent.mkdir(parents=True)
            warm_output = temp_root / "warmup.json"
            warm_command = incremental_command(
                workload, binary=binary_path, detectors=detector_path,
                fixture_root=fixture_path, cache_path=cache_path, output=warm_output,
                backend=backend,
            )
            _stdout, _stderr, warm_stats = runner(warm_command)
            warm_trial = _parse_trial(warm_output, warm_stats)
            if warm_trial.result_error or not cache_path.exists():
                raise BaselineCaptureError("incremental warmup did not publish a usable cache")
        for index in range(repetitions):
            if workload.workload_id == "incremental-cold-index":
                cache_path.unlink(missing_ok=True)
                cache_path.parent.mkdir(parents=True, exist_ok=True)
            output = temp_root / f"trial-{index}.json"
            command = incremental_command(
                workload, binary=binary_path, detectors=detector_path,
                fixture_root=fixture_path, cache_path=cache_path, output=output,
                backend=backend,
            )
            _stdout, _stderr, stats = runner(command)
            trials.append(_parse_trial(output, stats))
    return summarize_trials(
        workload.workload_id, backend, str(fixture_receipt["input_sha256"]),
        str(fixture_receipt["answer_sha256"]), sha256_file(binary_path), trials,
        expected_hashes, expected_gap,
    )


@contextlib.contextmanager
def fixture_http_server(fixture_root: pathlib.Path):
    """Serve exact canonical response bytes on a loopback-only ephemeral port."""
    responses = fixture_root / "input/responses"

    class QuietHandler(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            """Initialize the QuietHandler with directory pointing to fixture responses."""
            super().__init__(*args, directory=str(responses), **kwargs)

        def log_message(self, _format, *_args):
            """Suppress HTTP server log messages during fixture execution."""
            return

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), QuietHandler)
    worker = threading.Thread(target=server.serve_forever, name="fixture-http", daemon=True)
    worker.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=5)


def web_command(
    workload: Workload, *, binary: pathlib.Path, detectors: pathlib.Path,
    base_url: str, output: pathlib.Path, backend: str, fixture_root: pathlib.Path,
) -> list[str]:
    """Build one production WebSource command against canonical loopback bytes."""
    transport = json.loads((fixture_root / "input/transport.json").read_text(encoding="utf-8"))
    urls = [f"{base_url}/{pathlib.PurePosixPath(path).name}" for path in transport["payloads"]]
    return [
        str(binary), "scan", "--no-config", *_detector_args(detectors),
        "--backend", backend, "--no-gpu", "--daemon=off",
        "--allow-private-cloud-endpoint", "--format", "json-envelope",
        "--show-secrets", "--no-suppress-test-fixtures", "--dedup", "file",
        "--quiet", "--output", str(output), "--url", *urls,
    ]


def capture_web_baseline(
    workload: Workload, *, binary: str | pathlib.Path, detectors: str | pathlib.Path,
    fixture_root: str | pathlib.Path, fixture_receipt: dict[str, object],
    backend: str, repetitions: int = MIN_TRIALS, runner: TrialRunner = lambda command: run_measured(list(command)),
) -> BaselineSummary:
    """Measure WebSource fetch and extraction against deterministic HTTP responses."""
    if repetitions < MIN_TRIALS:
        raise BaselineCaptureError(
            f"baseline repetitions must be at least {MIN_TRIALS}, got {repetitions}"
        )
    binary_path = pathlib.Path(binary).resolve(strict=True)
    detector_path = _resolve_detectors(detectors)
    fixture_path = pathlib.Path(fixture_root).resolve(strict=True)
    expected_hashes, expected_gap = _fixture_expectation(fixture_path)
    trials: list[BaselineTrial] = []
    with tempfile.TemporaryDirectory(prefix=f"keyhog-web-{workload.workload_id}-") as raw:
        temp_root = pathlib.Path(raw)
        with fixture_http_server(fixture_path) as base_url:
            for index in range(repetitions):
                output = temp_root / f"trial-{index}.json"
                command = web_command(
                    workload, binary=binary_path, detectors=detector_path,
                    base_url=base_url, output=output, backend=backend,
                    fixture_root=fixture_path,
                )
                _stdout, _stderr, stats = runner(command)
                trials.append(_parse_trial(output, stats))
    return summarize_trials(
        workload.workload_id, backend, str(fixture_receipt["input_sha256"]),
        str(fixture_receipt["answer_sha256"]), sha256_file(binary_path), trials,
        expected_hashes, expected_gap,
    )


def concurrency_command(
    workload: Workload, *, binary: pathlib.Path, detectors: pathlib.Path | None,
    partition: pathlib.Path, output: pathlib.Path, backend: str,
) -> list[str]:
    """Build one child command in the independent-process concurrency cohort."""
    if workload.family != "concurrency":
        raise BaselineCaptureError(f"{workload.workload_id} is not concurrency")
    return [
        str(binary), "scan", "--no-config", *_detector_args(detectors),
        "--backend", backend, "--no-gpu", "--daemon=off", "--format",
        "json-envelope", "--show-secrets", "--no-default-excludes",
        "--no-suppress-test-fixtures", "--dedup", "file", "--quiet",
        "--output", str(output), str(partition),
    ]


def _combine_concurrent_trials(
    wall_ms: float, trials: Sequence[BaselineTrial]
) -> BaselineTrial:
    """Aggregate one simultaneous process cohort without hiding fleet memory."""
    minor = [trial.minor_page_faults for trial in trials]
    major = [trial.major_page_faults for trial in trials]
    errors = [trial.result_error for trial in trials if trial.result_error]
    unsuccessful = [trial.exit_code for trial in trials if trial.exit_code not in SUCCESS_EXIT_CODES]
    return BaselineTrial(
        wall_ms=wall_ms,
        peak_rss_kb=sum(trial.peak_rss_kb for trial in trials),
        minor_page_faults=(sum(value for value in minor if value is not None) if all(value is not None for value in minor) else None),
        major_page_faults=(sum(value for value in major if value is not None) if all(value is not None for value in major) else None),
        exit_code=unsuccessful[0] if unsuccessful else max(trial.exit_code for trial in trials),
        finding_count=sum(trial.finding_count for trial in trials),
        finding_hashes=tuple(sorted(hash_value for trial in trials for hash_value in trial.finding_hashes)),
        coverage_gap_count=sum(trial.coverage_gap_count for trial in trials),
        result_error="; ".join(errors),
    )


def capture_concurrency_baseline(
    workload: Workload, *, binary: str | pathlib.Path, detectors: str | pathlib.Path | None,
    fixture_root: str | pathlib.Path, fixture_receipt: dict[str, object],
    backend: str, repetitions: int = MIN_TRIALS, runner: TrialRunner = lambda command: run_measured(list(command)),
) -> BaselineSummary:
    """Measure four simultaneous independent KeyHog processes as one workload."""
    if repetitions < MIN_TRIALS:
        raise BaselineCaptureError(
            f"baseline repetitions must be at least {MIN_TRIALS}, got {repetitions}"
        )
    binary_path = pathlib.Path(binary).resolve(strict=True)
    detector_path = _resolve_detectors(detectors)
    fixture_path = pathlib.Path(fixture_root).resolve(strict=True)
    expected_hashes, expected_gap = _fixture_expectation(fixture_path)
    partitions = sorted((fixture_path / "input").glob("partition-*"))
    if len(partitions) != 4:
        raise BaselineCaptureError(f"concurrency fixture requires 4 partitions, got {len(partitions)}")
    cohort_trials: list[BaselineTrial] = []
    with tempfile.TemporaryDirectory(prefix="keyhog-concurrency-") as raw:
        output_root = pathlib.Path(raw)
        for repetition in range(repetitions):
            commands = []
            outputs = []
            for index, partition in enumerate(partitions):
                output = output_root / f"trial-{repetition}-process-{index}.json"
                outputs.append(output)
                commands.append(concurrency_command(
                    workload, binary=binary_path, detectors=detector_path,
                    partition=partition, output=output, backend=backend,
                ))
            started = time.perf_counter()
            with concurrent.futures.ThreadPoolExecutor(max_workers=len(commands)) as pool:
                measured = list(pool.map(runner, commands))
            wall_ms = (time.perf_counter() - started) * 1000.0
            child_trials = [
                _parse_trial(output, measured[index][2])
                for index, output in enumerate(outputs)
            ]
            cohort_trials.append(_combine_concurrent_trials(wall_ms, child_trials))
    return summarize_trials(
        workload.workload_id, backend, str(fixture_receipt["input_sha256"]),
        str(fixture_receipt["answer_sha256"]), sha256_file(binary_path), cohort_trials,
        expected_hashes, expected_gap,
    )


@contextlib.contextmanager
def fixture_daemon_remote_server(fixture_root: pathlib.Path):
    """Serve the canonical remote daemon payload through Slack's production API shape."""
    text=(fixture_root/"input/responses/secret.env").read_text().strip()
    class RemoteHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            """Handle GET requests for Slack remote daemon endpoints."""
            path=urllib.parse.urlparse(self.path).path
            if path=="/conversations.list": payload={"ok":True,"channels":[{"id":"C1","name":"general"}],"response_metadata":{"next_cursor":""}}
            elif path=="/conversations.history": payload={"ok":True,"messages":[{"user":"U1","text":text,"ts":"1700000000.000001"}],"has_more":False,"response_metadata":{"next_cursor":""}}
            else: self.send_error(404); return
            body=json.dumps(payload).encode(); self.send_response(200); self.send_header("content-type","application/json"); self.send_header("content-length",str(len(body))); self.end_headers(); self.wfile.write(body)
        def log_message(self,_format,*_args):
            """Suppress HTTP server log messages during daemon fixture execution."""
            return
    server=http.server.ThreadingHTTPServer(("127.0.0.1",0),RemoteHandler); worker=threading.Thread(target=server.serve_forever,daemon=True); worker.start()
    try: yield f"http://127.0.0.1:{server.server_port}"
    finally: server.shutdown(); server.server_close(); worker.join(timeout=5)


def capture_daemon_baseline(
    workload: Workload, *, binary: str | pathlib.Path, detectors: str | pathlib.Path,
    fixture_root: str | pathlib.Path, fixture_receipt: dict[str, object],
    backend: str, repetitions: int = MIN_TRIALS,
) -> BaselineSummary:
    """Measure warm single-file or stdin client requests against one owned daemon."""
    if workload.workload_id not in {
        "daemon-warm-single-file", "daemon-warm-stdin", "daemon-mass-filesystem",
        "daemon-mass-remote",
    }:
        raise BaselineCaptureError(
            f"daemon workload {workload.workload_id!r} lacks an executable driver"
        )
    if repetitions < MIN_TRIALS:
        raise BaselineCaptureError(
            f"baseline repetitions must be at least {MIN_TRIALS}, got {repetitions}"
        )
    binary_path = pathlib.Path(binary).resolve(strict=True)
    detector_path = _resolve_detectors(detectors)
    fixture_path = pathlib.Path(fixture_root).resolve(strict=True)
    expected_hashes, expected_gap = _fixture_expectation(fixture_path)
    is_stdin = workload.workload_id == "daemon-warm-stdin"
    is_mass_remote = workload.workload_id == "daemon-mass-remote"
    is_mass = workload.workload_id in {"daemon-mass-filesystem", "daemon-mass-remote"}
    source = fixture_path / (
        "input/request/stdin.bin" if is_stdin
        else "input/request/tree" if is_mass
        else "input/request/secret.env"
    )
    trials: list[BaselineTrial] = []
    with tempfile.TemporaryDirectory(prefix=f"keyhog-{workload.workload_id}-") as raw:
        output_root = pathlib.Path(raw)
        with contextlib.ExitStack() as stack:
            endpoint = stack.enter_context(fixture_daemon_remote_server(fixture_path)) if is_mass_remote else None
            daemon = stack.enter_context(OwnedKeyhogDaemon(
                binary_path, (), detector_path, backend, timeout=120, mass=is_mass
            ))
            warm_output = output_root / "warmup.json"
            if is_stdin:
                warm_stats = daemon.run_stdin_client(source, warm_output, 120)
            elif is_mass_remote:
                warm_stats = daemon.run_mass_remote_client(endpoint, warm_output, 120)
            elif is_mass:
                warm_stats = daemon.run_mass_client(source, warm_output, 120)
            else:
                warm_stats = daemon.run_client(source, warm_output, 120)
            warm_trial = _parse_trial(warm_output, warm_stats)
            if warm_trial.result_error:
                raise BaselineCaptureError("daemon warmup wrote no valid result")
            for index in range(repetitions):
                output = output_root / f"trial-{index}.json"
                if is_stdin:
                    stats = daemon.run_stdin_client(source, output, 120)
                elif is_mass_remote:
                    stats = daemon.run_mass_remote_client(endpoint, output, 120)
                elif is_mass:
                    stats = daemon.run_mass_client(source, output, 120)
                else:
                    stats = daemon.run_client(source, output, 120)
                trials.append(_parse_trial(output, stats))
            evidence = daemon.evidence()
            if evidence.scans_served != repetitions + 1 or evidence.active_scans != 0:
                raise BaselineCaptureError(
                    f"daemon served {evidence.scans_served} requests with "
                    f"{evidence.active_scans} active; expected {repetitions + 1}/0"
                )
    return summarize_trials(
        workload.workload_id, backend, str(fixture_receipt["input_sha256"]),
        str(fixture_receipt["answer_sha256"]), sha256_file(binary_path), trials,
        expected_hashes, expected_gap,
    )


def container_command(
    workload: Workload, *, binary: pathlib.Path, detectors: pathlib.Path,
    image: str, output: pathlib.Path, backend: str,
) -> list[str]:
    """Benchmark fixture component or validation handler."""
    if workload.family != "container":
        raise BaselineCaptureError(f"{workload.workload_id} is not container")
    return [
        str(binary), "scan", "--no-config", *_detector_args(detectors),
        "--backend", backend, "--no-gpu", "--daemon=off", "--format",
        "json-envelope", "--show-secrets", "--no-suppress-test-fixtures",
        "--dedup", "file", "--quiet", "--output", str(output),
        "--docker-image", image,
    ]


@contextlib.contextmanager
def prepared_container_image(fixture_root: pathlib.Path, input_sha256: str):
    """Import and remove one deterministic local rootfs image outside timed scans."""
    tag = f"keyhog-benchmark:{input_sha256[:16]}"
    with tempfile.TemporaryDirectory(prefix="keyhog-container-rootfs-") as raw:
        archive = pathlib.Path(raw) / "rootfs.tar"
        source = fixture_root / "input/layers/rootfs/secret.env"
        info = tarfile.TarInfo("secret.env")
        info.size = source.stat().st_size
        info.mode = 0o644
        info.mtime = 946684800
        with tarfile.open(archive, "w") as handle, source.open("rb") as payload:
            handle.addfile(info, payload)
        imported = subprocess.run(
            ["docker", "import", str(archive), tag], capture_output=True, text=True,
            check=False, timeout=120,
        )
        if imported.returncode != 0:
            raise BaselineCaptureError(f"docker import failed: {imported.stderr.strip()}")
        try:
            yield tag
        finally:
            removed = subprocess.run(
                ["docker", "image", "rm", "--force", tag], capture_output=True,
                text=True, check=False, timeout=120,
            )
            if removed.returncode != 0:
                raise BaselineCaptureError(f"docker image cleanup failed: {removed.stderr.strip()}")


def capture_container_baseline(
    workload: Workload, *, binary: str | pathlib.Path, detectors: str | pathlib.Path,
    fixture_root: str | pathlib.Path, fixture_receipt: dict[str, object],
    backend: str, repetitions: int = MIN_TRIALS, runner: TrialRunner = lambda command: run_measured(list(command)),
) -> BaselineSummary:
    """Benchmark fixture component or validation handler."""
    if repetitions < MIN_TRIALS:
        raise BaselineCaptureError(f"baseline repetitions must be at least {MIN_TRIALS}, got {repetitions}")
    binary_path = pathlib.Path(binary).resolve(strict=True)
    detector_path = _resolve_detectors(detectors)
    fixture_path = pathlib.Path(fixture_root).resolve(strict=True)
    expected_hashes, expected_gap = _fixture_expectation(fixture_path)
    trials: list[BaselineTrial] = []
    with tempfile.TemporaryDirectory(prefix="keyhog-container-results-") as raw:
        output_root = pathlib.Path(raw)
        with prepared_container_image(fixture_path, str(fixture_receipt["input_sha256"])) as image:
            for index in range(repetitions):
                output = output_root / f"trial-{index}.json"
                command = container_command(
                    workload, binary=binary_path, detectors=detector_path,
                    image=image, output=output, backend=backend,
                )
                _stdout, _stderr, stats = runner(command)
                trials.append(_parse_trial(output, stats))
    return summarize_trials(
        workload.workload_id, backend, str(fixture_receipt["input_sha256"]),
        str(fixture_receipt["answer_sha256"]), sha256_file(binary_path), trials,
        expected_hashes, expected_gap,
    )


@contextlib.contextmanager
def fixture_s3_server(fixture_root: pathlib.Path):
    """Serve one canonical path-style S3 bucket and object on loopback."""
    body = (fixture_root / "input/objects/secret.env").read_bytes()

    class S3Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            """Handle GET requests for S3 bucket listing and object retrieval."""
            parsed = urllib.parse.urlparse(self.path)
            query = urllib.parse.parse_qs(parsed.query)
            if parsed.path == "/storage/v1/b/benchmark/o" and query.get("alt") == ["json"]:
                listing = json.dumps({
                    "items": [{"name": "secret.env", "size": str(len(body)), "contentType": "text/plain"}]
                }, sort_keys=True).encode()
                self.send_response(200)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(listing)))
                self.end_headers(); self.wfile.write(listing)
            elif parsed.path == "/storage/v1/b/benchmark/o/secret.env" and query.get("alt") == ["media"]:
                self.send_response(200); self.send_header("content-type", "text/plain")
                self.send_header("content-length", str(len(body))); self.end_headers(); self.wfile.write(body)
            elif parsed.path == "/container" and query.get("comp") == ["list"]:
                listing = (
                    '<?xml version="1.0" encoding="utf-8"?>'
                    '<EnumerationResults><Blobs><Blob><Name>secret.env</Name>'
                    f'<Properties><Content-Length>{len(body)}</Content-Length>'
                    '<Content-Type>text/plain</Content-Type></Properties></Blob></Blobs>'
                    '<NextMarker /></EnumerationResults>'
                ).encode()
                self.send_response(200); self.send_header("content-type", "application/xml")
                self.send_header("content-length", str(len(listing))); self.end_headers(); self.wfile.write(listing)
            elif parsed.path == "/container/secret.env":
                self.send_response(200); self.send_header("content-type", "text/plain")
                self.send_header("content-length", str(len(body))); self.end_headers(); self.wfile.write(body)
            elif query.get("list-type") == ["2"]:
                listing = (
                    '<?xml version="1.0" encoding="UTF-8"?>'
                    '<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
                    '<Name>benchmark</Name><IsTruncated>false</IsTruncated>'
                    f'<Contents><Key>secret.env</Key><Size>{len(body)}</Size></Contents>'
                    '</ListBucketResult>'
                ).encode()
                self.send_response(200)
                self.send_header("content-type", "application/xml")
                self.send_header("content-length", str(len(listing)))
                self.end_headers()
                self.wfile.write(listing)
            elif parsed.path.endswith("/secret.env"):
                self.send_response(200)
                self.send_header("content-type", "text/plain")
                self.send_header("content-length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            else:
                self.send_error(404)

        def log_message(self, _format, *_args):
            """Suppress HTTP server log messages during S3 fixture execution."""
            return

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), S3Handler)
    worker = threading.Thread(target=server.serve_forever, name="fixture-s3", daemon=True)
    worker.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown(); server.server_close(); worker.join(timeout=5)


def cloud_command(
    workload: Workload, *, binary: pathlib.Path, detectors: pathlib.Path,
    endpoint: str, output: pathlib.Path, backend: str,
) -> list[str]:
    """Benchmark fixture component or validation handler."""
    command = [
        str(binary), "scan", "--no-config", *_detector_args(detectors),
        "--backend", backend, "--no-gpu", "--daemon=off",
        "--allow-private-cloud-endpoint", "--format", "json-envelope",
        "--show-secrets", "--no-suppress-test-fixtures", "--dedup", "file",
        "--quiet", "--output", str(output),
    ]
    if workload.workload_id == "cloud-s3-bucket":
        command.extend(["--s3-bucket", "benchmark", "--s3-endpoint", endpoint])
    elif workload.workload_id == "cloud-gcs-bucket":
        command.extend(["--gcs-bucket", "benchmark", "--gcs-endpoint", endpoint])
    elif workload.workload_id == "cloud-azure-container":
        command.extend(["--azure-container-url", f"{endpoint}/container"])
    else:
        raise BaselineCaptureError(f"unsupported cloud workload {workload.workload_id!r}")
    return command


def capture_cloud_baseline(
    workload: Workload, *, binary: str | pathlib.Path, detectors: str | pathlib.Path,
    fixture_root: str | pathlib.Path, fixture_receipt: dict[str, object],
    backend: str, repetitions: int = MIN_TRIALS, runner: TrialRunner = lambda command: run_measured(list(command)),
) -> BaselineSummary:
    """Benchmark fixture component or validation handler."""
    if workload.workload_id not in {
        "cloud-s3-bucket", "cloud-gcs-bucket", "cloud-azure-container",
    }:
        raise BaselineCaptureError(f"cloud workload {workload.workload_id!r} lacks a driver")
    if repetitions < MIN_TRIALS:
        raise BaselineCaptureError(f"baseline repetitions must be at least {MIN_TRIALS}, got {repetitions}")
    binary_path = pathlib.Path(binary).resolve(strict=True)
    detector_path = _resolve_detectors(detectors)
    fixture_path = pathlib.Path(fixture_root).resolve(strict=True)
    expected_hashes, expected_gap = _fixture_expectation(fixture_path)
    trials: list[BaselineTrial] = []
    with tempfile.TemporaryDirectory(prefix="keyhog-cloud-s3-") as raw:
        output_root = pathlib.Path(raw)
        with fixture_s3_server(fixture_path) as endpoint:
            for index in range(repetitions):
                output = output_root / f"trial-{index}.json"
                command = cloud_command(
                    workload, binary=binary_path, detectors=detector_path,
                    endpoint=endpoint, output=output, backend=backend,
                )
                _stdout, _stderr, stats = runner(command)
                trials.append(_parse_trial(output, stats))
    return summarize_trials(
        workload.workload_id, backend, str(fixture_receipt["input_sha256"]),
        str(fixture_receipt["answer_sha256"]), sha256_file(binary_path), trials,
        expected_hashes, expected_gap,
    )


def _proc_peak_rss_kb(pid: int) -> int:
    """Benchmark fixture component or validation handler."""
    for line in pathlib.Path(f"/proc/{pid}/status").read_text().splitlines():
        if line.startswith("VmHWM:"):
            return int(line.split()[1])
    return 0


def _drain_text_pipe(pipe, sink: list[str]) -> None:
    """Benchmark fixture component or validation handler."""
    for line in iter(pipe.readline, ""):
        sink.append(line)


def _watch_finding_hashes(lines: Sequence[str], event_name: str) -> tuple[str, ...]:
    """Benchmark fixture component or validation handler."""
    hashes: list[str] = []
    for line in lines:
        if event_name not in line:
            continue
        for field in line.split():
            if not field.startswith("sha256:"):
                continue
            value = field.removeprefix("sha256:")
            if len(value) == 64 and all(character in "0123456789abcdef" for character in value):
                hashes.append(value)
    return tuple(sorted(hashes))


def capture_watch_baseline(
    workload: Workload, *, binary: str | pathlib.Path, detectors: str | pathlib.Path,
    fixture_root: str | pathlib.Path, fixture_receipt: dict[str, object],
    backend: str, repetitions: int = MIN_TRIALS,
) -> BaselineSummary:
    """Measure finding latency after the production watch readiness banner."""
    if repetitions < MIN_TRIALS:
        raise BaselineCaptureError(f"baseline repetitions must be at least {MIN_TRIALS}, got {repetitions}")
    binary_path = pathlib.Path(binary).resolve(strict=True)
    detector_path = _resolve_detectors(detectors)
    fixture_path = pathlib.Path(fixture_root).resolve(strict=True)
    expected_hashes, expected_gap = _fixture_expectation(fixture_path)
    source = fixture_path / "input/events/secret.env"
    trials: list[BaselineTrial] = []
    with tempfile.TemporaryDirectory(prefix="keyhog-watch-") as raw:
        root = pathlib.Path(raw)
        for index in range(repetitions):
            event = root / f"event-{index}.env"
            stdout_lines: list[str] = []
            stderr_lines: list[str] = []
            process = subprocess.Popen(
                [str(binary_path), "watch", str(root), *_detector_args(detector_path),
                 "--backend", backend],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                start_new_session=True,
            )
            assert process.stdout is not None and process.stderr is not None
            threads = [
                threading.Thread(target=_drain_text_pipe, args=(process.stdout, stdout_lines), daemon=True),
                threading.Thread(target=_drain_text_pipe, args=(process.stderr, stderr_lines), daemon=True),
            ]
            for thread in threads: thread.start()
            ready_deadline = time.monotonic() + 30
            while "watching:" not in "".join(stderr_lines):
                if process.poll() is not None or time.monotonic() >= ready_deadline:
                    raise BaselineCaptureError(f"watch failed readiness: {''.join(stderr_lines)[-1000:]}")
                time.sleep(0.005)
            started = time.perf_counter()
            event.write_bytes(source.read_bytes())
            finding_deadline = time.monotonic() + 15
            while event.name not in "".join(stdout_lines):
                if process.poll() is not None or time.monotonic() >= finding_deadline:
                    raise BaselineCaptureError(
                        f"watch did not report {event.name}: stdout={''.join(stdout_lines)[-1000:]} "
                        f"stderr={''.join(stderr_lines)[-1000:]}"
                    )
                time.sleep(0.005)
            wall_ms = (time.perf_counter() - started) * 1000.0
            peak_rss = _proc_peak_rss_kb(process.pid)
            os.killpg(process.pid, signal.SIGTERM)
            try: process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL); process.wait(timeout=5)
            for thread in threads: thread.join(timeout=1)
            event.unlink()
            finding_hashes = _watch_finding_hashes(stdout_lines, event.name)
            trials.append(BaselineTrial(
                wall_ms=wall_ms, peak_rss_kb=peak_rss, minor_page_faults=None,
                major_page_faults=None, exit_code=0, finding_count=len(finding_hashes),
                finding_hashes=finding_hashes, coverage_gap_count=0,
                result_error="" if finding_hashes else "watch output lacked credential hashes",
            ))
    return summarize_trials(
        workload.workload_id, backend, str(fixture_receipt["input_sha256"]),
        str(fixture_receipt["answer_sha256"]), sha256_file(binary_path), trials,
        expected_hashes, expected_gap,
    )


@contextlib.contextmanager
def fixture_github_collaboration_server(fixture_root: pathlib.Path, workload_id: str):
    """Serve one canonical GitHub collaboration surface through its real API shape."""
    secret = (fixture_root / "input/responses/repository-secret.env").read_text().strip()

    class GitHubHandler(http.server.BaseHTTPRequestHandler):
        def _send(self, payload):
            """Send a JSON payload with standard HTTP 200 headers."""
            body = json.dumps(payload).encode(); self.send_response(200)
            self.send_header("content-type", "application/json"); self.send_header("content-length", str(len(body)))
            self.end_headers(); self.wfile.write(body)

        def do_GET(self):
            """Handle GET requests for REST GitHub collaboration endpoints."""
            path = urllib.parse.urlparse(self.path).path
            if workload_id.endswith("issues") and path == "/repos/acme/rocket/issues":
                return self._send([{"node_id":"I_fixture","number":7,"title":"fixture","body":secret,"user":{"login":"bench"},"updated_at":"2026-07-13T00:00:00Z"}])
            if workload_id.endswith("issues") and path.endswith("/issues/7/comments"): return self._send([])
            if workload_id.endswith("pull-requests") and path == "/repos/acme/rocket/pulls":
                return self._send([{"node_id":"PR_fixture","number":3,"title":"fixture","body":secret,"user":{"login":"bench"},"updated_at":"2026-07-13T00:00:00Z"}])
            if workload_id.endswith("pull-requests") and path in {"/repos/acme/rocket/issues/3/comments","/repos/acme/rocket/pulls/3/comments","/repos/acme/rocket/pulls/3/reviews"}: return self._send([])
            if workload_id.endswith("gists") and path == "/users/acme/gists": return self._send([{"id":"abc123"}])
            if workload_id.endswith("gists") and path == "/gists/abc123/commits": return self._send([{"version":"0123456789abcdef","committed_at":"2026-07-13T00:00:00Z","user":{"login":"bench"}}])
            if workload_id.endswith("gists") and path == "/gists/abc123/0123456789abcdef": return self._send({"id":"abc123","files":{"fixture.env":{"content":secret,"truncated":False}}})
            if workload_id.endswith("gists") and path == "/gists/abc123/comments": return self._send([])
            if workload_id.endswith("releases") and path == "/repos/acme/rocket/releases":
                return self._send([{"id":42,"node_id":"RE_fixture","tag_name":"v1","name":"fixture","body":secret,"author":{"login":"bench"},"created_at":"2026-07-13T00:00:00Z","published_at":None,"assets":[]}])
            self.send_error(404)

        def do_POST(self):
            """Handle POST requests for GraphQL GitHub discussion endpoints."""
            if urllib.parse.urlparse(self.path).path != "/graphql": self.send_error(404); return
            length = int(self.headers.get("content-length", "0")); body = self.rfile.read(length).decode()
            if workload_id.endswith("discussions") and "discussions(first:100" in body:
                return self._send({"data":{"repository":{"discussions":{"nodes":[{"id":"D_fixture","number":5,"title":"fixture","body":secret,"updatedAt":"2026-07-13T00:00:00Z","author":{"login":"bench"}}],"pageInfo":{"hasNextPage":False,"endCursor":None}}}}})
            if workload_id.endswith("discussions") and "discussion(number:$number)" in body:
                return self._send({"data":{"repository":{"discussion":{"comments":{"nodes":[],"pageInfo":{"hasNextPage":False,"endCursor":None}}}}}})
            self.send_error(404)

        def log_message(self, _format, *_args):
            """Suppress HTTP server log messages during GitHub fixture execution."""
            return

    server=http.server.ThreadingHTTPServer(("127.0.0.1",0),GitHubHandler); worker=threading.Thread(target=server.serve_forever,daemon=True); worker.start()
    try: yield f"http://127.0.0.1:{server.server_port}"
    finally: server.shutdown(); server.server_close(); worker.join(timeout=5)


def system_command(workload:Workload,*,binary:pathlib.Path,detectors:pathlib.Path,fixture_root:pathlib.Path,output:pathlib.Path,backend:str)->list[str]:
    """Benchmark fixture component or validation handler."""
    if workload.workload_id!="system-mounted-drives": raise BaselineCaptureError(f"unsupported system workload {workload.workload_id!r}")
    return [str(binary),"scan-system","--root",str(fixture_root/"input/mounts/home"),"--space","1M","--no-git-history",*_detector_args(detectors),"--backend",backend,"--output",str(output)]


def _parse_system_trial(output:pathlib.Path,stats:RunStats)->BaselineTrial:
    """Benchmark fixture component or validation handler."""
    if stats.timed_out or stats.exit_code not in SUCCESS_EXIT_CODES: raise BaselineCaptureError(f"scan-system exited {stats.exit_code}, timed_out={stats.timed_out}")
    findings=json.loads(output.read_text());
    if not isinstance(findings,list): raise BaselineCaptureError("scan-system report is not a finding array")
    hashes=[]
    for index,finding in enumerate(findings):
        digest=finding.get("credential_hash") if isinstance(finding,dict) else None
        if not isinstance(digest,str) or len(digest)!=64: raise BaselineCaptureError(f"scan-system finding[{index}] lacks a SHA-256 credential hash")
        hashes.append(digest)
    return BaselineTrial(stats.wall_ms,stats.peak_rss_kb,stats.minor_page_faults,stats.major_page_faults,stats.exit_code,len(findings),tuple(sorted(hashes)),0,"")


def capture_system_baseline(workload:Workload,*,binary:str|pathlib.Path,detectors:str|pathlib.Path,fixture_root:str|pathlib.Path,fixture_receipt:dict[str,object],backend:str,repetitions:int=MIN_TRIALS,runner:TrialRunner=lambda command:run_measured(list(command))):
    """Benchmark fixture component or validation handler."""
    if repetitions<MIN_TRIALS: raise BaselineCaptureError(f"baseline repetitions must be at least {MIN_TRIALS}")
    binary_path=pathlib.Path(binary).resolve(strict=True); detector_path = _resolve_detectors(detectors); fixture_path=pathlib.Path(fixture_root).resolve(strict=True); expected_hashes,expected_gap=_fixture_expectation(fixture_path); trials=[]
    with tempfile.TemporaryDirectory(prefix="keyhog-system-") as raw:
        temporary=pathlib.Path(raw)
        for index in range(repetitions):
            output=temporary/f"trial-{index}.json"; command=system_command(workload,binary=binary_path,detectors=detector_path,fixture_root=fixture_path,output=output,backend=backend); _stdout,_stderr,stats=runner(command); trials.append(_parse_system_trial(output,stats))
    return summarize_trials(workload.workload_id,backend,str(fixture_receipt["input_sha256"]),str(fixture_receipt["answer_sha256"]),sha256_file(binary_path),trials,expected_hashes,expected_gap)


@contextlib.contextmanager
def verification_connect_proxy(destination: pathlib.Path):
    """Terminate an explicit CONNECT tunnel for deterministic HTTPS verification."""
    key=destination/"proxy.key"; cert=destination/"proxy.crt"
    completed=subprocess.run(["openssl","req","-x509","-newkey","rsa:2048","-nodes","-keyout",str(key),"-out",str(cert),"-subj","/CN=example.com","-days","1"],capture_output=True,text=True,check=False,timeout=30)
    if completed.returncode!=0: raise BaselineCaptureError(f"verification certificate generation failed: {completed.stderr.strip()}")
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); context.load_cert_chain(cert,key); state={"requests":0}
    class ProxyHandler(socketserver.BaseRequestHandler):
        def handle(self):
            """Handle CONNECT tunnel establishment and TLS verification requests."""
            incoming=b""
            while b"\r\n\r\n" not in incoming and len(incoming)<16384:
                chunk=self.request.recv(4096)
                if not chunk: return
                incoming+=chunk
            if not incoming.startswith(b"CONNECT example.com:443 "):
                self.request.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n"); return
            self.request.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            try: tunnel=context.wrap_socket(self.request,server_side=True)
            except ssl.SSLError: return
            request=b""
            while b"\r\n\r\n" not in request and len(request)<65536:
                chunk=tunnel.recv(4096)
                if not chunk: return
                request+=chunk
            if not request.startswith(b"GET /verify ") or b"authorization: bearer " not in request.lower():
                tunnel.sendall(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"); tunnel.close(); return
            state["requests"]+=1; body=b'{"login":"benchmark"}'
            tunnel.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: "+str(len(body)).encode()+b"\r\nConnection: close\r\n\r\n"+body); tunnel.close()
    class ProxyServer(socketserver.ThreadingTCPServer): allow_reuse_address=True; daemon_threads=True
    server=ProxyServer(("127.0.0.1",0),ProxyHandler); worker=threading.Thread(target=server.serve_forever,daemon=True); worker.start()
    try: yield f"http://127.0.0.1:{server.server_address[1]}",state
    finally: server.shutdown(); server.server_close(); worker.join(timeout=5)


@contextlib.contextmanager
def verification_oob_connect_proxy(destination: pathlib.Path):
    """Serve verification and an encrypted Interactsh collector through CONNECT."""
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
    from cryptography.hazmat.decrepit.ciphers.modes import CFB
    key=destination/"oob-proxy.key"; cert=destination/"oob-proxy.crt"
    completed=subprocess.run(["openssl","req","-x509","-newkey","rsa:2048","-nodes","-keyout",str(key),"-out",str(cert),"-subj","/CN=example.com","-days","1"],capture_output=True,text=True,check=False,timeout=30)
    if completed.returncode!=0: raise BaselineCaptureError(f"OOB certificate generation failed: {completed.stderr.strip()}")
    tls=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); tls.load_cert_chain(cert,key)
    state={"register":0,"poll":0,"deregister":0,"verify":0,"registration":None,"pending":[]}; lock=threading.Lock()
    def encrypted_poll():
        """Poll pending out-of-band events and return AES-encrypted payloads."""
        with lock:
            registration=state["registration"]; pending=list(state["pending"]); state["pending"].clear()
        if not pending: return {"data":[],"extra":[]}
        aes_key=os.urandom(32); entries=[]
        for unique_id in pending:
            event=json.dumps({"protocol":"http","unique-id":unique_id[:24],"full-id":unique_id,"remote-address":"203.0.113.7","timestamp":"2026-08-05T00:00:00Z","raw-request":f"GET /{unique_id} HTTP/1.1"},separators=(",",":")).encode()
            iv=os.urandom(16); encrypted=Cipher(algorithms.AES(aes_key),CFB(iv)).encryptor().update(event)
            entries.append(base64.b64encode(iv+encrypted).decode())
        wrapped=registration["public_key"].encrypt(aes_key,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
        return {"data":entries,"extra":[],"aes_key":base64.b64encode(wrapped).decode()}
    class ProxyHandler(socketserver.BaseRequestHandler):
        def handle(self):
            """Handle OOB proxy requests, registration, polling, and verification."""
            incoming=b""
            while b"\r\n\r\n" not in incoming and len(incoming)<16384:
                chunk=self.request.recv(4096)
                if not chunk: return
                incoming+=chunk
            first=incoming.split(b"\r\n",1)[0].decode(errors="replace"); parts=first.split()
            if len(parts)<2 or parts[0]!="CONNECT" or parts[1] not in {"example.com:443","oast.fun:443"}:
                self.request.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n"); return
            target=parts[1].split(":",1)[0]; self.request.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            try: tunnel=tls.wrap_socket(self.request,server_side=True)
            except ssl.SSLError: return
            request=b""
            while b"\r\n\r\n" not in request and len(request)<65536:
                chunk=tunnel.recv(4096)
                if not chunk: return
                request+=chunk
            head,_,body=request.partition(b"\r\n\r\n"); lines=head.split(b"\r\n"); method,path,_version=lines[0].decode().split(" ",2)
            headers={}
            for line in lines[1:]:
                name,sep,value=line.partition(b":")
                if sep: headers[name.decode().lower()]=value.decode().strip()
            length=int(headers.get("content-length","0"))
            while len(body)<length: body+=tunnel.recv(length-len(body))
            status=200; response={}
            try:
                if target=="example.com" and method=="GET" and path.startswith("/verify?") and headers.get("authorization","").lower().startswith("bearer "):
                    query=urllib.parse.parse_qs(urllib.parse.urlparse(path).query); callback=query.get("callback",[""])[0]; host=urllib.parse.urlparse(callback).hostname or ""; unique=host.split(".",1)[0]
                    if len(unique)!=48: raise ValueError("missing 48-character Interactsh callback id")
                    with lock: state["verify"]+=1; state["pending"].append(unique)
                    response={"login":"benchmark"}
                elif target=="oast.fun" and method=="POST" and path=="/register":
                    request_json=json.loads(body[:length]); pem=base64.b64decode(request_json["public-key"]); public_key=serialization.load_pem_public_key(pem)
                    with lock: state["register"]+=1; state["registration"]={"id":request_json["correlation-id"],"secret":request_json["secret-key"],"public_key":public_key}
                elif target=="oast.fun" and method=="GET" and path.startswith("/poll?"):
                    with lock: state["poll"]+=1
                    response=encrypted_poll()
                elif target=="oast.fun" and method=="POST" and path=="/deregister":
                    with lock: state["deregister"]+=1
                else: status=404; response={"error":"not found"}
            except Exception as exc: status=400; response={"error":str(exc)}
            payload=json.dumps(response,separators=(",",":")).encode(); reason=b"OK" if status==200 else b"Error"
            tunnel.sendall(b"HTTP/1.1 "+str(status).encode()+b" "+reason+b"\r\nContent-Type: application/json\r\nContent-Length: "+str(len(payload)).encode()+b"\r\nConnection: close\r\n\r\n"+payload); tunnel.close()
    class ProxyServer(socketserver.ThreadingTCPServer): allow_reuse_address=True; daemon_threads=True
    server=ProxyServer(("127.0.0.1",0),ProxyHandler); worker=threading.Thread(target=server.serve_forever,daemon=True); worker.start()
    try: yield f"http://127.0.0.1:{server.server_address[1]}",state
    finally: server.shutdown(); server.server_close(); worker.join(timeout=5)


def prepare_oob_verification_detectors(destination:pathlib.Path)->pathlib.Path:
    """Publish one verifier that requires both HTTP success and an OOB callback."""
    destination.mkdir(); text=(pathlib.Path(__file__).resolve().parents[2]/"detectors/github-classic-pat.toml").read_text(encoding="utf-8")
    text=text.replace('url = "https://api.github.com/user"','url = "https://example.com/verify?callback={{interactsh.url}}"').replace('allowed_domains = ["api.github.com"]','allowed_domains = ["example.com"]')
    text += '\n[detector.verify.oob]\nprotocol = "http"\ntimeout_secs = 3\npolicy = "oob_and_http"\n'
    (destination/"github-classic-pat.toml").write_text(text,encoding="utf-8"); return destination


def prepare_verification_detectors(destination:pathlib.Path)->pathlib.Path:
    """Publish one real PAT detector whose verifier targets the controlled proxy origin."""
    destination.mkdir(); text=(pathlib.Path(__file__).resolve().parents[2]/"detectors/github-classic-pat.toml").read_text(encoding="utf-8")
    text=text.replace('url = "https://api.github.com/user"','url = "https://example.com/verify"').replace('allowed_domains = ["api.github.com"]','allowed_domains = ["example.com"]')
    (destination/"github-classic-pat.toml").write_text(text,encoding="utf-8"); return destination


def verification_command(workload:Workload,*,binary:pathlib.Path,detectors:pathlib.Path|None,fixture_root:pathlib.Path,proxy:str,output:pathlib.Path,backend:str)->list[str]:
    """Benchmark fixture component or validation handler."""
    command=[str(binary),"scan","--no-config",*_detector_args(detectors),"--backend",backend,"--no-gpu","--daemon=off","--format","json-envelope","--show-secrets","--no-suppress-test-fixtures","--dedup","file","--quiet","--output",str(output),"--proxy",proxy,"--insecure","--verify"]
    if workload.workload_id=="verification-batched-service": command.append("--verify-batch")
    elif workload.workload_id=="verification-out-of-band": command.extend(["--verify-oob","--oob-server","oast.fun","--oob-timeout","3"])
    elif workload.workload_id!="verification-live-credentials": raise BaselineCaptureError(f"verification workload {workload.workload_id!r} lacks an executable driver")
    command.append(str(fixture_root/"input/findings/secret.env")); return command


def capture_verification_baseline(workload:Workload,*,binary:str|pathlib.Path,detectors:str|pathlib.Path,fixture_root:str|pathlib.Path,fixture_receipt:dict[str,object],backend:str,repetitions:int=MIN_TRIALS,runner:TrialRunner=lambda command:run_measured(list(command))):
    """Benchmark fixture component or validation handler."""
    if repetitions<MIN_TRIALS: raise BaselineCaptureError(f"baseline repetitions must be at least {MIN_TRIALS}")
    binary_path=pathlib.Path(binary).resolve(strict=True); fixture_path=pathlib.Path(fixture_root).resolve(strict=True); expected_hashes,expected_gap=_fixture_expectation(fixture_path); trials=[]
    with tempfile.TemporaryDirectory(prefix="keyhog-verify-") as raw:
        temporary=pathlib.Path(raw); is_oob=workload.workload_id=="verification-out-of-band"
        detector_path=(prepare_oob_verification_detectors if is_oob else prepare_verification_detectors)(temporary/"detectors")
        proxy_context=verification_oob_connect_proxy(temporary) if is_oob else verification_connect_proxy(temporary)
        with proxy_context as (proxy,state):
            for index in range(repetitions):
                counter="verify" if is_oob else "requests"; before=state[counter]; output=temporary/f"trial-{index}.json"; command=verification_command(workload,binary=binary_path,detectors=detector_path,fixture_root=fixture_path,proxy=proxy,output=output,backend=backend); _stdout,_stderr,stats=runner(command)
                if state[counter]<=before: raise BaselineCaptureError(f"verification trial {index} made no HTTPS verifier request: {_stderr.strip()}")
                trial=_parse_trial(output,stats); envelope=json.loads(output.read_text()); findings=envelope["findings"]; verdicts={finding.get("verification") for finding in findings}
                if verdicts!={"live"}: raise BaselineCaptureError(f"verification trial {index} verdicts were {sorted(str(v) for v in verdicts)}")
                if is_oob and (state["register"]<index+1 or state["poll"]<index+1 or state["deregister"]<index+1 or {finding.get("metadata",{}).get("oob_observed") for finding in findings}!={"true"}): raise BaselineCaptureError(f"verification trial {index} lacked complete OOB evidence: state={state}, metadata={[finding.get('metadata') for finding in findings]}")
                trials.append(trial)
    return summarize_trials(workload.workload_id,backend,str(fixture_receipt["input_sha256"]),str(fixture_receipt["answer_sha256"]),sha256_file(binary_path),trials,expected_hashes,expected_gap)


@contextlib.contextmanager
def fixture_hosted_group_server(fixture_root: pathlib.Path, destination: pathlib.Path, platform: str):
    """Serve one GitLab group or Bitbucket workspace with a same-origin smart Git repo."""
    filename="project-secret.env" if platform=="gitlab" else "repository-secret.env"
    source=destination/"source"; source.mkdir(parents=True); _git_run(source,"init","--quiet","--initial-branch=main")
    (source/"secret.env").write_bytes((fixture_root/"input/responses"/filename).read_bytes()); _git_run(source,"add","secret.env"); _git_run(source,"commit","--quiet","-m","fixture repository")
    bare=destination/"repository.git"; completed=subprocess.run(["git","clone","--quiet","--bare",str(source),str(bare)],capture_output=True,text=True,check=False,timeout=30)
    if completed.returncode!=0: raise BaselineCaptureError(f"{platform} bare clone failed: {completed.stderr.strip()}")
    class HostedHandler(http.server.BaseHTTPRequestHandler):
        def _git_backend(self):
            """Execute git http-backend CGI script for smart HTTP requests."""
            parsed=urllib.parse.urlparse(self.path); length=int(self.headers.get("content-length","0")); request=self.rfile.read(length) if length else b""
            env=dict(os.environ); env.update({"GIT_PROJECT_ROOT":str(destination),"GIT_HTTP_EXPORT_ALL":"1","PATH_INFO":parsed.path,"QUERY_STRING":parsed.query,"REQUEST_METHOD":self.command,"CONTENT_TYPE":self.headers.get("content-type",""),"CONTENT_LENGTH":str(length),"REMOTE_ADDR":"127.0.0.1"})
            completed=subprocess.run(["git","http-backend"],input=request,capture_output=True,check=False,env=env,timeout=30)
            header_bytes,separator,body=completed.stdout.partition(b"\r\n\r\n")
            if not separator: header_bytes,separator,body=completed.stdout.partition(b"\n\n")
            if completed.returncode!=0 or not separator: self.send_error(500); return
            status=200; headers=[]
            for raw in header_bytes.replace(b"\r",b"").splitlines():
                name,value=raw.decode("latin-1").split(":",1)
                if name.lower()=="status": status=int(value.strip().split()[0])
                else: headers.append((name,value.strip()))
            self.send_response(status)
            for name,value in headers: self.send_header(name,value)
            self.end_headers(); self.wfile.write(body)
        def do_GET(self):
            """Handle GET requests for hosted group platform API or Git smart HTTP."""
            parsed=urllib.parse.urlparse(self.path); host,port=self.server.server_address; clone=f"http://{host}:{port}/repository.git"
            if platform=="gitlab" and parsed.path=="/api/v4/groups/acme/projects":
                payload=[{"path_with_namespace":"acme/repository","http_url_to_repo":clone}]
            elif platform=="bitbucket" and parsed.path=="/2.0/repositories/acme":
                payload={"values":[{"slug":"repository","links":{"clone":[{"name":"https","href":clone}]}}],"next":None}
            else: self._git_backend(); return
            body=json.dumps(payload).encode(); self.send_response(200); self.send_header("content-type","application/json"); self.send_header("content-length",str(len(body))); self.end_headers(); self.wfile.write(body)
        def do_POST(self):
            """Handle POST requests for Git smart HTTP upload/receive service."""
            self._git_backend()
        def log_message(self,_format,*_args):
            """Suppress HTTP server log messages during hosted group fixture execution."""
            return
    server=http.server.ThreadingHTTPServer(("127.0.0.1",0),HostedHandler); worker=threading.Thread(target=server.serve_forever,daemon=True); worker.start()
    try: yield f"http://127.0.0.1:{server.server_port}"
    finally: server.shutdown(); server.server_close(); worker.join(timeout=5)


def hosted_group_command(workload: Workload, *, binary:pathlib.Path, detectors:pathlib.Path|None, endpoint:str, output:pathlib.Path, backend:str)->list[str]:
    """Benchmark fixture component or validation handler."""
    base=[str(binary),"scan","--no-config",*_detector_args(detectors),"--backend",backend,"--no-gpu","--daemon=off","--allow-private-cloud-endpoint","--format","json-envelope","--show-secrets","--no-suppress-test-fixtures","--dedup","file","--quiet","--output",str(output)]
    if workload.family=="gitlab": return base+["--gitlab-group","acme","--gitlab-token","benchmark-token","--gitlab-endpoint",endpoint]
    if workload.family=="bitbucket": return base+["--bitbucket-workspace","acme","--bitbucket-username","benchmark-user","--bitbucket-token","benchmark-token","--bitbucket-endpoint",endpoint+"/2.0"]
    raise BaselineCaptureError(f"unsupported hosted group family {workload.family!r}")


def capture_hosted_group_baseline(workload: Workload, *, binary:str|pathlib.Path, detectors:str|pathlib.Path, fixture_root:str|pathlib.Path, fixture_receipt:dict[str,object], backend:str, repetitions:int=MIN_TRIALS, runner:TrialRunner=lambda command:run_measured(list(command))):
    """Benchmark fixture component or validation handler."""
    if repetitions<MIN_TRIALS: raise BaselineCaptureError(f"baseline repetitions must be at least {MIN_TRIALS}")
    binary_path=pathlib.Path(binary).resolve(strict=True); detector_path = _resolve_detectors(detectors); fixture_path=pathlib.Path(fixture_root).resolve(strict=True); expected_hashes,expected_gap=_fixture_expectation(fixture_path); trials=[]
    with tempfile.TemporaryDirectory(prefix=f"keyhog-{workload.family}-") as raw:
        temporary=pathlib.Path(raw)
        with fixture_hosted_group_server(fixture_path,temporary/"served",workload.family) as endpoint:
            for index in range(repetitions):
                output=temporary/f"trial-{index}.json"; command=hosted_group_command(workload,binary=binary_path,detectors=detector_path,endpoint=endpoint,output=output,backend=backend); _stdout,_stderr,stats=runner(command); trials.append(_parse_trial(output,stats))
    return summarize_trials(workload.workload_id,backend,str(fixture_receipt["input_sha256"]),str(fixture_receipt["answer_sha256"]),sha256_file(binary_path),trials,expected_hashes,expected_gap)


@contextlib.contextmanager
def fixture_github_org_server(fixture_root: pathlib.Path, destination: pathlib.Path):
    """Serve organization listing and same-origin Git repository over loopback HTTP."""
    source=destination/"source"; source.mkdir(parents=True); _git_run(source,"init","--quiet","--initial-branch=main")
    (source/"secret.env").write_bytes((fixture_root/"input/responses/repository-secret.env").read_bytes())
    _git_run(source,"add","secret.env"); _git_run(source,"commit","--quiet","-m","fixture repository")
    bare=destination/"repository.git"
    completed=subprocess.run(["git","clone","--quiet","--bare",str(source),str(bare)],capture_output=True,text=True,check=False,timeout=30)
    if completed.returncode != 0: raise BaselineCaptureError(f"organization bare clone failed: {completed.stderr.strip()}")
    completed=subprocess.run(["git","--git-dir",str(bare),"update-server-info"],capture_output=True,text=True,check=False,timeout=30)
    if completed.returncode != 0: raise BaselineCaptureError(f"organization server-info failed: {completed.stderr.strip()}")
    class OrgHandler(http.server.BaseHTTPRequestHandler):
        def _git_backend(self):
            """Execute git http-backend CGI script for GitHub org requests."""
            parsed=urllib.parse.urlparse(self.path); length=int(self.headers.get("content-length","0")); request=self.rfile.read(length) if length else b""
            env=dict(os.environ); env.update({"GIT_PROJECT_ROOT":str(destination),"GIT_HTTP_EXPORT_ALL":"1","PATH_INFO":parsed.path,"QUERY_STRING":parsed.query,"REQUEST_METHOD":self.command,"CONTENT_TYPE":self.headers.get("content-type",""),"CONTENT_LENGTH":str(length),"REMOTE_ADDR":"127.0.0.1"})
            completed=subprocess.run(["git","http-backend"],input=request,capture_output=True,check=False,env=env,timeout=30)
            if completed.returncode != 0: self.send_error(500); return
            header_bytes,separator,body=completed.stdout.partition(b"\r\n\r\n")
            if not separator: header_bytes,separator,body=completed.stdout.partition(b"\n\n")
            if not separator: self.send_error(500); return
            status=200; headers=[]
            for raw in header_bytes.replace(b"\r",b"").splitlines():
                name,value=raw.decode("latin-1").split(":",1)
                if name.lower()=="status": status=int(value.strip().split()[0])
                else: headers.append((name,value.strip()))
            self.send_response(status)
            for name,value in headers: self.send_header(name,value)
            self.end_headers(); self.wfile.write(body)
        def do_GET(self):
            """Handle GET requests for GitHub org repos listing or Git smart HTTP."""
            if urllib.parse.urlparse(self.path).path == "/orgs/acme/repos":
                host,port=self.server.server_address; payload=[{"name":"repository","clone_url":f"http://{host}:{port}/repository.git"}]
                body=json.dumps(payload).encode(); self.send_response(200); self.send_header("content-type","application/json"); self.send_header("content-length",str(len(body))); self.end_headers(); self.wfile.write(body); return
            self._git_backend()
        def do_POST(self):
            """Handle POST requests for Git smart HTTP upload/receive service."""
            self._git_backend()
        def log_message(self,_format,*_args):
            """Suppress HTTP server log messages during GitHub org fixture execution."""
            return
    server=http.server.ThreadingHTTPServer(("127.0.0.1",0),OrgHandler); worker=threading.Thread(target=server.serve_forever,daemon=True); worker.start()
    try: yield f"http://127.0.0.1:{server.server_port}"
    finally: server.shutdown(); server.server_close(); worker.join(timeout=5)


def github_org_command(*,binary:pathlib.Path,detectors:pathlib.Path|None,endpoint:str,output:pathlib.Path,backend:str)->list[str]:
    """Benchmark fixture component or validation handler."""
    return [str(binary),"scan","--no-config",*_detector_args(detectors),"--backend",backend,"--no-gpu","--daemon=off","--allow-private-cloud-endpoint","--format","json-envelope","--show-secrets","--no-suppress-test-fixtures","--dedup","file","--quiet","--output",str(output),"--github-org","acme","--github-token","benchmark-token","--github-api-endpoint",endpoint]


@contextlib.contextmanager
def fixture_git_http_server(repository: pathlib.Path, destination: pathlib.Path):
    """Serve one bare repository through Git's deterministic dumb-HTTP protocol."""
    bare = destination / "wiki.git"
    completed = subprocess.run(["git","clone","--quiet","--bare",str(repository),str(bare)],capture_output=True,text=True,check=False,timeout=30)
    if completed.returncode != 0: raise BaselineCaptureError(f"wiki bare clone failed: {completed.stderr.strip()}")
    completed = subprocess.run(["git","--git-dir",str(bare),"update-server-info"],capture_output=True,text=True,check=False,timeout=30)
    if completed.returncode != 0: raise BaselineCaptureError(f"wiki server-info failed: {completed.stderr.strip()}")
    class GitHandler(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            """Initialize GitHandler with directory set to the target destination."""
            super().__init__(*args, directory=str(destination), **kwargs)
        def log_message(self, _format, *_args):
            """Suppress HTTP server log messages during dumb Git HTTP fixture execution."""
            return
    server=http.server.ThreadingHTTPServer(("127.0.0.1",0),GitHandler); worker=threading.Thread(target=server.serve_forever,daemon=True); worker.start()
    try: yield f"http://127.0.0.1:{server.server_port}/wiki.git"
    finally: server.shutdown(); server.server_close(); worker.join(timeout=5)


def github_collaboration_command(workload: Workload, *, binary: pathlib.Path, detectors: pathlib.Path, endpoint: str, output: pathlib.Path, backend: str, wiki_url: str | None = None) -> list[str]:
    """Benchmark fixture component or validation handler."""
    surface={"github-collaboration-issues":"issues","github-collaboration-pull-requests":"pull-requests","github-collaboration-discussions":"discussions","github-collaboration-gists":"gists","github-collaboration-releases":"releases","github-collaboration-wiki":"wiki"}.get(workload.workload_id)
    if surface is None: raise BaselineCaptureError(f"GitHub collaboration workload {workload.workload_id!r} lacks an API driver")
    command=[str(binary),"scan","--no-config",*_detector_args(detectors),"--backend",backend,"--no-gpu","--daemon=off","--allow-private-cloud-endpoint","--format","json-envelope","--show-secrets","--no-suppress-test-fixtures","--dedup","file","--quiet","--output",str(output),"--github-collaboration","acme/rocket","--github-token","benchmark-token","--github-api-endpoint",endpoint,f"--github-{surface}"]
    if surface == "wiki":
        if wiki_url is None: raise BaselineCaptureError("GitHub wiki baseline requires an explicit clone URL")
        command.extend(["--github-wiki-url",wiki_url])
    return command


def capture_github_baseline(workload: Workload, *, binary: str | pathlib.Path, detectors: str | pathlib.Path, fixture_root: str | pathlib.Path, fixture_receipt: dict[str, object], backend: str, repetitions: int = MIN_TRIALS, runner: TrialRunner = lambda command: run_measured(list(command))):
    """Benchmark fixture component or validation handler."""
    if repetitions < MIN_TRIALS: raise BaselineCaptureError(f"baseline repetitions must be at least {MIN_TRIALS}")
    binary_path=pathlib.Path(binary).resolve(strict=True); detector_path = _resolve_detectors(detectors); fixture_path=pathlib.Path(fixture_root).resolve(strict=True)
    expected_hashes,expected_gap=_fixture_expectation(fixture_path); trials=[]
    if workload.workload_id == "github-organization-repositories":
        with tempfile.TemporaryDirectory(prefix="keyhog-github-org-") as raw:
            temporary=pathlib.Path(raw); served=temporary/"served"
            with fixture_github_org_server(fixture_path,served) as endpoint:
                for index in range(repetitions):
                    output=temporary/f"trial-{index}.json"; command=github_org_command(binary=binary_path,detectors=detector_path,endpoint=endpoint,output=output,backend=backend)
                    _stdout,_stderr,stats=runner(command); trials.append(_parse_trial(output,stats))
        return summarize_trials(workload.workload_id,backend,str(fixture_receipt["input_sha256"]),str(fixture_receipt["answer_sha256"]),sha256_file(binary_path),trials,expected_hashes,expected_gap)
    with tempfile.TemporaryDirectory(prefix="keyhog-github-") as raw, fixture_github_collaboration_server(fixture_path,workload.workload_id) as endpoint:
        temporary = pathlib.Path(raw)
        wiki_url = None
        if workload.workload_id == "github-collaboration-wiki":
            repository = temporary / "wiki-source"; repository.mkdir()
            _git_run(repository, "init", "--quiet", "--initial-branch=main")
            (repository / "Home.md").write_bytes((fixture_path / "input/responses/repository-secret.env").read_bytes())
            _git_run(repository, "add", "Home.md"); _git_run(repository, "commit", "--quiet", "-m", "fixture wiki revision")
            git_server = fixture_git_http_server(repository, temporary / "git-http")
            (temporary / "git-http").mkdir()
        else:
            git_server = contextlib.nullcontext(None)
        with git_server as wiki_url:
            for index in range(repetitions):
                output=temporary/f"trial-{index}.json"; command=github_collaboration_command(workload,binary=binary_path,detectors=detector_path,endpoint=endpoint,output=output,backend=backend,wiki_url=wiki_url)
                _stdout,_stderr,stats=runner(command); trials.append(_parse_trial(output,stats))
    return summarize_trials(workload.workload_id,backend,str(fixture_receipt["input_sha256"]),str(fixture_receipt["answer_sha256"]),sha256_file(binary_path),trials,expected_hashes,expected_gap)


@contextlib.contextmanager
def fixture_slack_server(fixture_root: pathlib.Path):
    """Serve one canonical channel and message through the Slack Web API shape."""
    payload = json.loads((fixture_root / "input/responses/messages.json").read_text())
    text = payload["messages"][0]["text"]

    class SlackHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            """Handle GET requests for Slack API conversations listing and history."""
            parsed = urllib.parse.urlparse(self.path)
            if parsed.path == "/conversations.list":
                body = json.dumps({"ok": True, "channels": [{"id": "C1", "name": "general"}], "response_metadata": {"next_cursor": ""}}).encode()
            elif parsed.path == "/conversations.history":
                body = json.dumps({"ok": True, "messages": [{"user": "U1", "text": text, "ts": "1700000000.000001"}], "has_more": False, "response_metadata": {"next_cursor": ""}}).encode()
            else:
                self.send_error(404); return
            self.send_response(200); self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(body))); self.end_headers(); self.wfile.write(body)

        def log_message(self, _format, *_args):
            """Suppress HTTP server log messages during Slack fixture execution."""
            return

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), SlackHandler)
    worker = threading.Thread(target=server.serve_forever, name="fixture-slack", daemon=True); worker.start()
    try: yield f"http://127.0.0.1:{server.server_port}"
    finally: server.shutdown(); server.server_close(); worker.join(timeout=5)


def capture_slack_baseline(
    workload: Workload, *, binary: str | pathlib.Path, detectors: str | pathlib.Path,
    fixture_root: str | pathlib.Path, fixture_receipt: dict[str, object],
    backend: str, repetitions: int = MIN_TRIALS, runner: TrialRunner = lambda command: run_measured(list(command)),
) -> BaselineSummary:
    """Benchmark fixture component or validation handler."""
    if repetitions < MIN_TRIALS:
        raise BaselineCaptureError(f"baseline repetitions must be at least {MIN_TRIALS}, got {repetitions}")
    binary_path = pathlib.Path(binary).resolve(strict=True); detector_path = _resolve_detectors(detectors)
    fixture_path = pathlib.Path(fixture_root).resolve(strict=True)
    expected_hashes, expected_gap = _fixture_expectation(fixture_path); trials=[]
    with tempfile.TemporaryDirectory(prefix="keyhog-slack-") as raw:
        with fixture_slack_server(fixture_path) as endpoint:
            for index in range(repetitions):
                output=pathlib.Path(raw)/f"trial-{index}.json"
                command=[str(binary_path),"scan","--no-config",*_detector_args(detector_path),"--backend",backend,"--no-gpu","--daemon=off","--allow-private-cloud-endpoint","--format","json-envelope","--show-secrets","--no-suppress-test-fixtures","--dedup","file","--quiet","--output",str(output),"--source",f"slack:xoxb-benchmark\n{endpoint}"]
                _stdout,_stderr,stats=runner(command); trials.append(_parse_trial(output,stats))
    return summarize_trials(workload.workload_id,backend,str(fixture_receipt["input_sha256"]),str(fixture_receipt["answer_sha256"]),sha256_file(binary_path),trials,expected_hashes,expected_gap)

def capture_filesystem_baseline(
    workload: Workload,
    *,
    binary: str | pathlib.Path,
    detectors: str | pathlib.Path | None,
    fixture_root: str | pathlib.Path,
    fixture_receipt: dict[str, object],
    backend: str,
    repetitions: int = MIN_TRIALS,
    runner: TrialRunner = lambda command: run_measured(list(command)),
) -> BaselineSummary:
    """Capture repeated whole-process evidence for one filesystem workload."""
    if repetitions < MIN_TRIALS:
        raise BaselineCaptureError(
            f"baseline repetitions must be at least {MIN_TRIALS}, got {repetitions}"
        )
    binary_path = pathlib.Path(binary).resolve(strict=True)
    detector_path = _resolve_detectors(detectors)
    fixture_path = pathlib.Path(fixture_root).resolve(strict=True)
    expected_hashes, expected_gap = _fixture_expectation(fixture_path)
    trials: list[BaselineTrial] = []
    with tempfile.TemporaryDirectory(prefix=f"keyhog-baseline-{workload.workload_id}-") as raw:
        output_dir = pathlib.Path(raw)
        for index in range(repetitions):
            output = output_dir / f"trial-{index}.json"
            command = filesystem_command(
                workload,
                binary=binary_path,
                detectors=detector_path,
                fixture_root=fixture_path,
                output=output,
                backend=backend,
            )
            with runtime_fixture_state(fixture_path):
                _stdout, _stderr, stats = runner(command)
            trials.append(_parse_trial(output, stats))
    return summarize_trials(
        workload.workload_id,
        backend,
        str(fixture_receipt["input_sha256"]),
        str(fixture_receipt["answer_sha256"]),
        sha256_file(binary_path),
        trials,
        expected_hashes,
        expected_gap,
    )


def bind_diagnostic_provenance(artifact:dict[str,object], generation:dict[str,object]) -> dict[str,object]:
    """Bind a diagnostic artifact to one validated workload-baseline generation."""
    fields=("catalog_sha256","fixture_lock_sha256","target_matrix_sha256","target_id","host_evidence")
    missing=[field for field in fields if field not in generation]
    if missing: raise BaselineCaptureError(f"baseline generation lacks diagnostic provenance: {missing}")
    for field in ("binary_sha256","backend"):
        if artifact.get(field)!=generation.get(field): raise BaselineCaptureError(f"diagnostic {field} differs from baseline generation")
    rebound=json.loads(json.dumps(artifact))
    for field in fields: rebound[field]=generation[field]
    return rebound


def startup_profile_command(workload: Workload, *, binary:pathlib.Path, detectors:pathlib.Path, fixture_root:pathlib.Path, output:pathlib.Path, profile_output:pathlib.Path, backend:str) -> list[str]:
    """Build one whole-process scan that also emits the internal causal profile."""
    if workload.workload_id!="filesystem-single-tiny-file":
        raise BaselineCaptureError("startup profiling requires filesystem-single-tiny-file")
    command=filesystem_command(workload,binary=binary,detectors=detectors,fixture_root=fixture_root,output=output,backend=backend)
    command[-1:-1]=["--profile-out",str(profile_output)]
    return command


def parse_startup_profile(profile:dict[str,object],stats:RunStats) -> dict[str,object]:
    """Bind internal stage time to the measured whole-process wall interval."""
    wall_ns=profile.get("wall_time_ns")
    stages=profile.get("stages")
    if not isinstance(wall_ns,int) or isinstance(wall_ns,bool) or wall_ns<=0:
        raise BaselineCaptureError("startup profile lacks positive wall_time_ns")
    if not isinstance(stages,list):
        raise BaselineCaptureError("startup profile stages must be an array")
    stage_ns:dict[str,int]={}
    for index,row in enumerate(stages):
        if not isinstance(row,dict) or not isinstance(row.get("stage"),str) or not isinstance(row.get("elapsed_ns"),int) or isinstance(row.get("elapsed_ns"),bool) or row["elapsed_ns"]<0:
            raise BaselineCaptureError(f"startup profile stage[{index}] is malformed")
        name=str(row["stage"]); stage_ns[name]=stage_ns.get(name,0)+int(row["elapsed_ns"])
    external_wall_ns=round(stats.wall_ms*1_000_000)
    return {"external_wall_ns":external_wall_ns,"profile_session_wall_ns":wall_ns,"outside_profile_session_ns":max(0,external_wall_ns-wall_ns),"stages_ns":dict(sorted(stage_ns.items()))}


def capture_startup_baseline(workload:Workload,*,binary:str|pathlib.Path,detectors:str|pathlib.Path,fixture_root:str|pathlib.Path,fixture_receipt:dict[str,object],backend:str,repetitions:int=MIN_TRIALS,runner:TrialRunner=lambda command:run_measured(list(command))) -> dict[str,object]:
    """Capture startup attribution while preserving the external process boundary."""
    if repetitions<MIN_TRIALS: raise BaselineCaptureError(f"baseline repetitions must be at least {MIN_TRIALS}")
    binary_path=pathlib.Path(binary).resolve(strict=True); detector_path = _resolve_detectors(detectors); fixture_path=pathlib.Path(fixture_root).resolve(strict=True); rows=[]
    with tempfile.TemporaryDirectory(prefix="keyhog-startup-") as raw:
        temporary=pathlib.Path(raw)
        for index in range(repetitions):
            output=temporary/f"result-{index}.json"; profile_output=temporary/f"profile-{index}.json"; command=startup_profile_command(workload,binary=binary_path,detectors=detector_path,fixture_root=fixture_path,output=output,profile_output=profile_output,backend=backend); _stdout,stderr,stats=runner(command)
            if stats.timed_out or stats.exit_code not in SUCCESS_EXIT_CODES: raise BaselineCaptureError(f"startup trial {index} exited {stats.exit_code}: {stderr.strip()}")
            try: profile=json.loads(profile_output.read_text())
            except (OSError,json.JSONDecodeError) as exc: raise BaselineCaptureError(f"startup trial {index} profile is unavailable: {exc}") from exc
            rows.append(parse_startup_profile(profile,stats))
    outside=[float(row["outside_profile_session_ns"]) for row in rows]; session=[float(row["profile_session_wall_ns"]) for row in rows]
    return {"schema_version":1,"workload_id":workload.workload_id,"backend":backend,"binary_sha256":sha256_file(binary_path),"fixture_input_sha256":fixture_receipt["input_sha256"],"fixture_answer_sha256":fixture_receipt["answer_sha256"],"repetitions":repetitions,"p50_profile_session_ns":statistics.median(session),"p95_profile_session_ns":percentile_nearest_rank(session,0.95),"p50_outside_profile_session_ns":statistics.median(outside),"p95_outside_profile_session_ns":percentile_nearest_rank(outside,0.95),"trials":rows}


def workload_measurement_axes(workload: Workload) -> dict[str, str]:
    """Describe the route actually measured for one workload row."""
    workload_id = workload.workload_id
    if workload_id.startswith("daemon-warm-"):
        process_state = "warm"
        page_cache_state = "warm"
        execution_route = "warm-daemon"
    elif workload_id.startswith("daemon-mass-"):
        process_state = "steady"
        page_cache_state = "steady"
        execution_route = "mass-daemon"
    elif workload.family == "incremental":
        process_state = "cold"
        page_cache_state = "incremental-warm"
        execution_route = "in-process"
    else:
        process_state = "cold"
        page_cache_state = "uncontrolled"
        execution_route = "in-process"
    if workload.execution_routes != (execution_route,):
        raise BaselineCaptureError(
            f"{workload_id} declares execution routes {list(workload.execution_routes)!r}, "
            f"but its production capture measures only {execution_route!r}"
        )
    return {
        "policy": "default",
        "process_state": process_state,
        "page_cache_state": page_cache_state,
        "output_format": "text" if workload.family == "watch" else "json-envelope",
        "execution_route": execution_route,
    }


def capture_baseline_catalog(
    *,
    catalog_path: str | pathlib.Path,
    fixture_lock_path: str | pathlib.Path,
    fixture_root: str | pathlib.Path,
    target_matrix_path: str | pathlib.Path,
    target_id: str,
    binary: str | pathlib.Path,
    backend: str,
    detectors: str | pathlib.Path | None = None,
    execution_pack_manifest: str | pathlib.Path | None = None,
    repetitions: int = MIN_TRIALS,
    only: set[str] | None = None,
    families: set[str] | None = None,
    host_probe: Callable[[TargetIdentity], dict[str, object]] = capture_target_evidence,
) -> dict[str, object]:
    """Capture selected supported workload families into one provenance-bound baseline."""
    if (detectors is None) == (execution_pack_manifest is None):
        raise BaselineCaptureError(
            "select exactly one detector mode: --detectors or --execution-pack-manifest"
        )
    binary_path = pathlib.Path(binary).resolve(strict=True)
    manifest_path: pathlib.Path | None = None
    runtime_provenance: dict[str, object] | None = None
    if execution_pack_manifest is not None:
        manifest_path, runtime_provenance = _load_execution_pack_manifest(
            execution_pack_manifest, binary_path
        )
    catalog = load_workload_catalog(catalog_path)
    lock = validate_fixture_lock(catalog_path, fixture_lock_path)
    target_matrix = load_target_matrix(target_matrix_path)
    targets = {target.target_id: target for target in target_matrix.targets}
    if target_id not in targets:
        raise BaselineCaptureError(f"target matrix does not define {target_id!r}")
    host_evidence = host_probe(targets[target_id])
    lock_rows = {row["workload_id"]: row for row in lock["workloads"]}
    selected_families = families or {workload.family for workload in catalog.workloads}
    unsupported_families = sorted(selected_families - {"filesystem", "stdin", "git", "incremental", "web", "concurrency", "daemon", "container", "cloud", "watch", "slack", "github", "gitlab", "bitbucket", "verification", "system"})
    if unsupported_families:
        raise BaselineCaptureError(f"unsupported baseline families: {unsupported_families}")
    eligible_ids = {
        workload.workload_id for workload in catalog.workloads
        if workload.family in selected_families
    }
    unknown = sorted((only or set()) - eligible_ids)
    if unknown:
        raise BaselineCaptureError(f"unknown selected baseline workloads: {unknown}")
    summaries: list[tuple[Workload, BaselineSummary]] = []
    workload_detector_provenance: dict[str, dict[str, object]] = {}
    with _execution_pack_capture(manifest_path) as pack_observations:
        for workload in sorted(catalog.workloads, key=lambda item: item.workload_id):
            if workload.family not in selected_families:
                continue
            if only is not None and workload.workload_id not in only:
                continue
            capture = {
                "filesystem": capture_filesystem_baseline,
                "stdin": capture_stdin_baseline,
                "git": capture_git_baseline,
                "incremental": capture_incremental_baseline,
                "web": capture_web_baseline,
                "concurrency": capture_concurrency_baseline,
                "daemon": capture_daemon_baseline,
                "container": capture_container_baseline,
                "cloud": capture_cloud_baseline,
                "watch": capture_watch_baseline,
                "slack": capture_slack_baseline,
                "github": capture_github_baseline,
                "gitlab": capture_hosted_group_baseline,
                "bitbucket": capture_hosted_group_baseline,
                "verification": capture_verification_baseline,
                "system": capture_system_baseline,
            }[workload.family]
            observation_start = len(pack_observations) if pack_observations is not None else 0
            summaries.append((workload,
                capture(
                    workload, binary=binary_path, detectors=detectors,
                    fixture_root=pathlib.Path(fixture_root) / workload.workload_id,
                    fixture_receipt=lock_rows[workload.workload_id], backend=backend,
                    repetitions=repetitions,
                )
            ))
            if pack_observations is not None:
                observed = set(pack_observations[observation_start:])
                if len(observed) > 1:
                    raise BaselineCaptureError(
                        "execution-pack detector provenance drifted within "
                        f"{workload.workload_id}: {sorted(observed)}"
                    )
                if observed:
                    detector_digest, detector_count, corpus_digest = next(iter(observed))
                    workload_detector_provenance[workload.workload_id] = {
                        "mode": "scan-envelope",
                        "scan_detector_digest": detector_digest,
                        "detector_count": detector_count,
                        "detector_corpus_digest": corpus_digest,
                    }
                else:
                    workload_detector_provenance[workload.workload_id] = {
                        "mode": "manifest",
                        "execution_pack_detector_digest": runtime_provenance[
                            "detector_digest"
                        ],
                    }
    if runtime_provenance is not None:
        _current_manifest_path, current_runtime = _load_execution_pack_manifest(
            manifest_path, binary_path
        )
        if current_runtime != runtime_provenance:
            raise BaselineCaptureError(
                "execution-pack manifest or candidate binary drifted during capture"
            )
        runtime_provenance["workload_detector_provenance"] = (
            workload_detector_provenance
        )
    rows=[]
    for workload,summary in summaries:
        row=summary.to_json(); row.update(workload_measurement_axes(workload)); rows.append(row)
    payload = {
        "schema_version": (
            PACK_BASELINE_SCHEMA_VERSION
            if runtime_provenance is not None else BASELINE_SCHEMA_VERSION
        ),
        "catalog_sha256": lock["catalog_sha256"],
        "fixture_lock_sha256": sha256_file(fixture_lock_path),
        "target_matrix_sha256": target_matrix_sha256(target_matrix_path),
        "target_id": target_id,
        "host_evidence": host_evidence,
        "binary_sha256": sha256_file(binary_path),
        "backend": backend,
        "repetitions": repetitions,
        "workloads": rows,
    }
    if runtime_provenance is not None:
        payload["runtime_provenance"] = runtime_provenance
    return payload



def validate_baseline_payload(
    payload: dict[str, object],
    *,
    catalog_path: str | pathlib.Path,
    fixture_lock_path: str | pathlib.Path,
    target_matrix_path: str | pathlib.Path,
    expected_workload_ids: set[str] | None = None,
    binary_path: str | pathlib.Path | None = None,
    execution_pack_manifest_path: str | pathlib.Path | None = None,
) -> None:
    """Reject stale, partial, duplicated, or arithmetically inconsistent baselines."""
    schema_version = payload.get("schema_version")
    if schema_version not in {
        BASELINE_SCHEMA_VERSION,
        LEGACY_PACK_BASELINE_SCHEMA_VERSION,
        PACK_BASELINE_SCHEMA_VERSION,
    }:
        raise BaselineCaptureError("baseline schema version is not supported")
    required = {
        "schema_version", "catalog_sha256", "fixture_lock_sha256",
        "target_matrix_sha256", "target_id", "host_evidence", "binary_sha256", "backend",
        "repetitions", "workloads",
    }
    if schema_version in {
        LEGACY_PACK_BASELINE_SCHEMA_VERSION,
        PACK_BASELINE_SCHEMA_VERSION,
    }:
        required.add("runtime_provenance")
    if set(payload) != required:
        raise BaselineCaptureError(
            f"baseline fields differ: missing={sorted(required - set(payload))}, "
            f"extra={sorted(set(payload) - required)}"
        )
    runtime_workloads: set[str] | None = None
    if schema_version in {
        LEGACY_PACK_BASELINE_SCHEMA_VERSION,
        PACK_BASELINE_SCHEMA_VERSION,
    }:
        if binary_path is None or execution_pack_manifest_path is None:
            raise BaselineCaptureError(
                "execution-pack baseline validation requires its binary and manifest"
            )
        binary = pathlib.Path(binary_path).resolve(strict=True)
        _manifest_path, expected_runtime = _load_execution_pack_manifest(
            execution_pack_manifest_path, binary
        )
        runtime = payload["runtime_provenance"]
        provenance_field = (
            "workload_detector_provenance"
            if schema_version == PACK_BASELINE_SCHEMA_VERSION
            else None
        )
        legacy_fields = {
            "scan_detector_digest", "detector_count", "detector_corpus_digest",
        }
        runtime_fields = set(expected_runtime) | (
            {provenance_field} if provenance_field is not None else legacy_fields
        )
        if not isinstance(runtime, dict) or set(runtime) != runtime_fields:
            raise BaselineCaptureError("execution-pack runtime provenance fields differ")
        for field, expected in expected_runtime.items():
            if runtime.get(field) != expected:
                raise BaselineCaptureError(
                    f"execution-pack runtime provenance differs in {field}"
                )
        if provenance_field is None:
            provenance_rows = {"*": {field: runtime.get(field) for field in legacy_fields}}
        else:
            provenance_rows = runtime.get(provenance_field)
            if not isinstance(provenance_rows, dict):
                raise BaselineCaptureError(
                    "execution-pack workload detector provenance is malformed"
                )
            runtime_workloads = set(provenance_rows)
        for workload_id, provenance in provenance_rows.items():
            malformed = not isinstance(workload_id, str) or not workload_id
            if provenance_field is None:
                malformed = malformed or (
                    not isinstance(provenance, dict)
                    or set(provenance) != legacy_fields
                    or not isinstance(provenance.get("scan_detector_digest"), str)
                    or not provenance["scan_detector_digest"]
                    or isinstance(provenance.get("detector_count"), bool)
                    or not isinstance(provenance.get("detector_count"), int)
                    or provenance["detector_count"] <= 0
                    or not isinstance(provenance.get("detector_corpus_digest"), str)
                    or not provenance["detector_corpus_digest"]
                )
            elif not isinstance(provenance, dict):
                malformed = True
            elif provenance.get("mode") == "scan-envelope":
                malformed = malformed or (
                    set(provenance) != legacy_fields | {"mode"}
                    or not isinstance(provenance.get("scan_detector_digest"), str)
                    or not provenance["scan_detector_digest"]
                    or isinstance(provenance.get("detector_count"), bool)
                    or not isinstance(provenance.get("detector_count"), int)
                    or provenance["detector_count"] <= 0
                    or not isinstance(provenance.get("detector_corpus_digest"), str)
                    or not provenance["detector_corpus_digest"]
                )
            elif provenance.get("mode") == "manifest":
                malformed = malformed or (
                    set(provenance) != {
                        "mode", "execution_pack_detector_digest",
                    }
                    or provenance.get("execution_pack_detector_digest")
                    != expected_runtime["detector_digest"]
                )
            else:
                malformed = True
            if malformed:
                raise BaselineCaptureError(
                    "execution-pack detector corpus provenance is malformed"
                )
    catalog = load_workload_catalog(catalog_path)
    lock = validate_fixture_lock(catalog_path, fixture_lock_path)
    matrix = load_target_matrix(target_matrix_path)
    if payload["catalog_sha256"] != lock["catalog_sha256"]:
        raise BaselineCaptureError("baseline catalog digest is stale")
    if payload["fixture_lock_sha256"] != sha256_file(fixture_lock_path):
        raise BaselineCaptureError("baseline fixture lock digest is stale")
    if payload["target_matrix_sha256"] != target_matrix_sha256(target_matrix_path):
        raise BaselineCaptureError("baseline target matrix digest is stale")
    if payload["target_id"] not in {target.target_id for target in matrix.targets}:
        raise BaselineCaptureError("baseline target id is not pinned")
    host_evidence = payload["host_evidence"]
    host_fields = {
        "os", "arch", "cpu", "logical_cores", "ram_mb", "gpu",
        "gpu_vram_mb", "gpu_driver", "kernel",
    }
    if not isinstance(host_evidence, dict) or set(host_evidence) != host_fields:
        raise BaselineCaptureError("baseline host evidence fields are incomplete")
    target = next(target for target in matrix.targets if target.target_id == payload["target_id"])
    exact_matches = {
        "os": target.os, "arch": target.arch, "cpu": target.cpu,
        "logical_cores": target.logical_cores, "gpu": target.gpu,
        "gpu_driver": target.gpu_driver,
    }
    if any(host_evidence[field] != expected for field, expected in exact_matches.items()):
        raise BaselineCaptureError("baseline host evidence differs from its pinned target")
    if host_evidence["ram_mb"] < target.min_ram_mb or host_evidence["gpu_vram_mb"] < target.min_gpu_vram_mb:
        raise BaselineCaptureError("baseline host memory is below its pinned target")
    if binary_path is not None and payload["binary_sha256"] != sha256_file(binary_path):
        raise BaselineCaptureError("baseline binary digest does not match the supplied executable")
    repetitions = payload["repetitions"]
    if not isinstance(repetitions, int) or isinstance(repetitions, bool) or repetitions < MIN_TRIALS:
        raise BaselineCaptureError("baseline repetitions are below the statistical floor")
    rows = payload["workloads"]
    if not isinstance(rows, list):
        raise BaselineCaptureError("baseline workloads must be an array")
    catalog_ids = {workload.workload_id for workload in catalog.workloads}
    lock_rows = {row["workload_id"]: row for row in lock["workloads"]}
    seen: set[str] = set()
    for row in rows:
        if not isinstance(row, dict):
            raise BaselineCaptureError("baseline workload row must be an object")
        workload_id = row.get("workload_id")
        if workload_id not in catalog_ids:
            raise BaselineCaptureError(f"baseline has unknown workload {workload_id!r}")
        if workload_id in seen:
            raise BaselineCaptureError(f"baseline duplicates workload {workload_id!r}")
        seen.add(workload_id)
        receipt = lock_rows[workload_id]
        for field in ("input_sha256", "answer_sha256"):
            if row.get(f"fixture_{field}") != receipt[field]:
                raise BaselineCaptureError(f"baseline {workload_id} {field} is stale")
        if row.get("binary_sha256") != payload["binary_sha256"]:
            raise BaselineCaptureError(f"baseline {workload_id} binary digest differs")
        if row.get("backend") != payload["backend"]:
            raise BaselineCaptureError(f"baseline {workload_id} backend differs")
        expected_axes=workload_measurement_axes(next(item for item in catalog.workloads if item.workload_id==workload_id))
        observed_axes={field:row.get(field) for field in expected_axes}
        if observed_axes!=expected_axes:
            raise BaselineCaptureError(f"baseline {workload_id} measurement axes differ: expected={expected_axes}, observed={observed_axes}")
        trials = row.get("trials")
        if not isinstance(trials, list) or len(trials) != repetitions:
            raise BaselineCaptureError(f"baseline {workload_id} trial count differs")
        walls = [trial["wall_ms"] for trial in trials]
        rss = [trial["peak_rss_kb"] for trial in trials]
        minor_faults = [trial.get("minor_page_faults") for trial in trials]
        major_faults = [trial.get("major_page_faults") for trial in trials]
        for v in minor_faults:
            if v is not None and (isinstance(v, bool) or not isinstance(v, int) or v < 0):
                raise BaselineCaptureError(f"baseline {workload_id} minor page fault value is invalid: {v!r}")
        for v in major_faults:
            if v is not None and (isinstance(v, bool) or not isinstance(v, int) or v < 0):
                raise BaselineCaptureError(f"baseline {workload_id} major page fault value is invalid: {v!r}")
        measured_minor = [v for v in minor_faults if v is not None]
        measured_major = [v for v in major_faults if v is not None]
        if 0 < len(measured_minor) < len(trials):
            raise BaselineCaptureError(f"baseline {workload_id} minor page faults are partially measured across trials")
        if 0 < len(measured_major) < len(trials):
            raise BaselineCaptureError(f"baseline {workload_id} major page faults are partially measured across trials")
        if len(measured_minor) == 0 and any(
            row.get(field) is not None
            for field in ("p50_minor_page_faults", "p95_minor_page_faults")
        ):
            raise BaselineCaptureError(f"baseline {workload_id} contains minor page fault summary metrics but trials have no minor page fault measurements")
        if len(measured_major) == 0 and any(
            row.get(field) is not None
            for field in ("p50_major_page_faults", "p95_major_page_faults")
        ):
            raise BaselineCaptureError(f"baseline {workload_id} contains major page fault summary metrics but trials have no major page fault measurements")
        expected_stats = {
            "p50_wall_ms": statistics.median(walls),
            "p95_wall_ms": percentile_nearest_rank(walls, 0.95),
            "median_peak_rss_kb": statistics.median(rss),
            "max_peak_rss_kb": max(rss),
        }
        if len(measured_minor) == len(trials):
            expected_stats["p50_minor_page_faults"] = statistics.median(measured_minor)
            expected_stats["p95_minor_page_faults"] = percentile_nearest_rank(measured_minor, 0.95)
        if len(measured_major) == len(trials):
            expected_stats["p50_major_page_faults"] = statistics.median(measured_major)
            expected_stats["p95_major_page_faults"] = percentile_nearest_rank(measured_major, 0.95)
        for field, expected in expected_stats.items():
            if row.get(field) != expected:
                raise BaselineCaptureError(
                    f"baseline {workload_id} {field} does not match its trials"
                )
    if runtime_workloads is not None and runtime_workloads != seen:
        raise BaselineCaptureError(
            "execution-pack workload detector provenance coverage differs: "
            f"missing={sorted(seen - runtime_workloads)}, "
            f"extra={sorted(runtime_workloads - seen)}"
        )
    if expected_workload_ids is not None and seen != expected_workload_ids:
        raise BaselineCaptureError(
            "baseline workload coverage differs: "
            f"missing={sorted(expected_workload_ids - seen)}, "
            f"extra={sorted(seen - expected_workload_ids)}"
        )



def rebind_fixture_lock(
    payload: dict[str, object], *, fixture_lock_path: str | pathlib.Path,
    fixture_root: str | pathlib.Path,
) -> dict[str, object]:
    """Rebind unchanged fixture bytes and recompute parity after oracle metadata changes."""
    rebound = json.loads(json.dumps(payload))
    lock = json.loads(pathlib.Path(fixture_lock_path).read_text(encoding="utf-8"))
    lock_rows = {row["workload_id"]: row for row in lock["workloads"]}
    root = pathlib.Path(fixture_root)
    for row in rebound["workloads"]:
        workload_id = row["workload_id"]
        receipt = lock_rows.get(workload_id)
        if receipt is None:
            raise BaselineCaptureError(f"new fixture lock omits {workload_id!r}")
        if (
            row["fixture_input_sha256"] != receipt["input_sha256"]
            or row["fixture_answer_sha256"] != receipt["answer_sha256"]
        ):
            raise BaselineCaptureError(
                f"cannot rebind {workload_id}: input or answer bytes changed"
            )
        expected_hashes, expected_gap = _fixture_expectation(root / workload_id)
        row["parity_ok"] = all(
            not trial["result_error"]
            and tuple(trial["finding_hashes"]) == expected_hashes
            and bool(trial["coverage_gap_count"]) == expected_gap
            for trial in row["trials"]
        )
    rebound["fixture_lock_sha256"] = sha256_file(fixture_lock_path)
    return rebound

def merge_baseline_payloads(payloads: Sequence[dict[str, object]]) -> dict[str, object]:
    """Merge disjoint workload shards only when all provenance fields match exactly."""
    if not payloads:
        raise BaselineCaptureError("cannot merge an empty baseline set")
    common_fields = (
        "schema_version", "catalog_sha256", "fixture_lock_sha256",
        "target_matrix_sha256", "target_id", "host_evidence", "binary_sha256", "backend",
        "repetitions",
    )
    merged = {field: payloads[0][field] for field in common_fields}
    rows: list[dict[str, object]] = []
    seen: set[str] = set()
    for payload in payloads:
        for field in common_fields:
            if payload.get(field) != merged[field]:
                raise BaselineCaptureError(f"baseline shards differ in {field}")
        workload_rows = payload.get("workloads")
        if not isinstance(workload_rows, list):
            raise BaselineCaptureError("baseline shard workloads must be an array")
        for row in workload_rows:
            workload_id = row.get("workload_id") if isinstance(row, dict) else None
            if not isinstance(workload_id, str) or workload_id in seen:
                raise BaselineCaptureError(f"baseline shard duplicates {workload_id!r}")
            seen.add(workload_id)
            rows.append(row)
    merged["workloads"] = sorted(rows, key=lambda row: row["workload_id"])
    return merged

@contextlib.contextmanager
def exclusive_capture_lock(target_id: str):
    """Reject overlapping captures that would contaminate wall and RSS evidence."""
    safe="".join(char if char.isalnum() or char in "-_" else "_" for char in target_id)
    path=pathlib.Path(tempfile.gettempdir())/f"keyhog-baseline-{safe}.lock"
    handle=path.open("a+b")
    try:
        handle.seek(0); handle.write(b"\0"); handle.flush(); handle.seek(0)
        try:
            if os.name=="nt":
                import msvcrt
                msvcrt.locking(handle.fileno(),msvcrt.LK_NBLCK,1)
            else:
                import fcntl
                fcntl.flock(handle.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
        except OSError as exc:
            raise BaselineCaptureError(f"another baseline capture already owns target {target_id!r}; concurrent captures invalidate wall and RSS evidence") from exc
        yield
    finally:
        try:
            handle.seek(0)
            if os.name=="nt":
                import msvcrt
                msvcrt.locking(handle.fileno(),msvcrt.LK_UNLCK,1)
            else:
                import fcntl
                fcntl.flock(handle.fileno(),fcntl.LOCK_UN)
        except OSError:
            pass
        handle.close()


def _main() -> int:
    """Benchmark fixture component or validation handler."""
    parser = argparse.ArgumentParser(description="Capture canonical KeyHog baselines")
    parser.add_argument("--catalog", default="workload-catalog.toml")
    parser.add_argument("--fixture-lock", default="workload-fixtures.lock.json")
    parser.add_argument("--fixtures", required=True)
    parser.add_argument("--target-matrix", default="target-matrix.toml")
    parser.add_argument("--target", required=True)
    parser.add_argument("--binary", required=True)
    detector_mode = parser.add_mutually_exclusive_group(required=True)
    detector_mode.add_argument("--detectors")
    detector_mode.add_argument("--execution-pack-manifest")
    parser.add_argument("--backend", choices=("cpu", "simd"), required=True)
    parser.add_argument("--repetitions", type=int, default=MIN_TRIALS)
    parser.add_argument("--only", nargs="*")
    parser.add_argument("--family", action="append", choices=("filesystem", "stdin", "git", "incremental", "web", "concurrency", "daemon", "container", "cloud", "watch", "slack", "github", "gitlab", "bitbucket", "verification", "system"))
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    with exclusive_capture_lock(args.target):
        payload = capture_baseline_catalog(
            catalog_path=args.catalog,
            fixture_lock_path=args.fixture_lock,
            fixture_root=args.fixtures,
            target_matrix_path=args.target_matrix,
            target_id=args.target,
            binary=args.binary,
            detectors=args.detectors,
            execution_pack_manifest=args.execution_pack_manifest,
            backend=args.backend,
            repetitions=args.repetitions,
            only=set(args.only) if args.only else None,
            families=set(args.family) if args.family else None,
        )
    destination = pathlib.Path(args.out)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(f".{destination.name}.tmp-{os.getpid()}")
    try:
        temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        temporary.replace(destination)
    finally:
        temporary.unlink(missing_ok=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
