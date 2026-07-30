"""Reproducible KeyHog CPU, reader, storage, size, and partition scaling evidence."""

from __future__ import annotations

import argparse
import concurrent.futures
import contextlib
import datetime as dt
import hashlib
import json
import math
import os
import pathlib
import shutil
import statistics
import tempfile
import time
from dataclasses import dataclass
from typing import Callable, Iterator, Sequence

from . import hardware
from .executable_snapshot import sibling_executable_snapshot
from .keyhog_version import assert_keyhog_binary_current
from .schema import Host
from .scanners.base import run_measured
from .scanners.keyhog import KeyhogScanner, resolve_keyhog_binary

SCHEMA = "keyhog-readme-scaling-v1"
BEGIN = "<!-- BENCH:scaling:BEGIN -->"
END = "<!-- BENCH:scaling:END -->"
DEFAULT_WORKLOADS = (
    ("small", 256, 32 * 1024),
    ("medium", 1024, 64 * 1024),
    ("large", 2048, 128 * 1024),
)


@dataclass(frozen=True)
class Workload:
    """One deterministic regular-file workload."""

    name: str
    files: int
    bytes_per_file: int

    @property
    def total_bytes(self) -> int:
        return self.files * self.bytes_per_file

    def to_json(self, digest: str) -> dict[str, object]:
        return {
            "name": self.name,
            "files": self.files,
            "bytes_per_file": self.bytes_per_file,
            "total_bytes": self.total_bytes,
            "sha256": digest,
        }


@dataclass(frozen=True)
class Storage:
    """A named storage root and its operator-visible filesystem identity."""

    label: str
    root: pathlib.Path
    filesystem: str
    device_id: int

    def to_json(self) -> dict[str, object]:
        return {
            "label": self.label,
            "filesystem": self.filesystem,
            "device_id": self.device_id,
        }


@dataclass(frozen=True)
class Trial:
    """One completed scan or concurrent scan group."""

    wall_ms: float
    peak_rss_kb: int
    max_process_rss_kb: int
    exit_codes: tuple[int, ...]
    finding_count: int

    def to_json(self) -> dict[str, object]:
        return {
            "wall_ms": round(self.wall_ms, 3),
            "peak_rss_kb": self.peak_rss_kb,
            "max_process_rss_kb": self.max_process_rss_kb,
            "exit_codes": list(self.exit_codes),
            "finding_count": self.finding_count,
        }


@dataclass(frozen=True)
class Case:
    """One point on a scaling panel."""

    panel: str
    label: str
    storage: str
    workload: str
    processes: int
    threads_per_process: int
    reader_threads: int
    total_bytes: int
    total_files: int


def _safe_content(file_index: int, size: int) -> bytes:
    line = (
        f"ordinary_keyhog_scaling_record file={file_index:06d} "
        "classification=public value=not-a-credential\n"
    ).encode("ascii")
    return (line * ((size + len(line) - 1) // len(line)))[:size]


def corpus_digest(root: pathlib.Path) -> str:
    """Hash relative paths, lengths, and bytes for every generated file."""
    digest = hashlib.sha256()
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        relative = path.relative_to(root).as_posix().encode("utf-8")
        digest.update(len(relative).to_bytes(4, "big"))
        digest.update(relative)
        size = path.stat().st_size
        digest.update(size.to_bytes(8, "big"))
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    return digest.hexdigest()


def prepare_corpus(root: pathlib.Path, workload: Workload) -> str:
    """Create or atomically repair one byte-exact deterministic corpus."""
    target = root / workload.name
    manifest = root / f".{workload.name}.keyhog-scaling.json"
    expected = {
        "schema": 1,
        "name": workload.name,
        "files": workload.files,
        "bytes_per_file": workload.bytes_per_file,
    }
    try:
        current = json.loads(manifest.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, json.JSONDecodeError):
        current = None
    if isinstance(current, dict) and all(
        current.get(key) == value for key, value in expected.items()
    ):
        try:
            files = list(target.iterdir())
        except OSError:
            files = []
        if (
            len(files) == workload.files
            and all(
                item.is_file() and item.stat().st_size == workload.bytes_per_file
                for item in files
            )
            and isinstance(current.get("sha256"), str)
        ):
            observed = corpus_digest(target)
            if observed == current["sha256"]:
                return observed

    root.mkdir(parents=True, exist_ok=True)
    staging = root / f".{workload.name}.staging-{os.getpid()}"
    if staging.exists():
        shutil.rmtree(staging)
    staging.mkdir()
    try:
        for index in range(workload.files):
            (staging / f"record-{index:06d}.txt").write_bytes(
                _safe_content(index, workload.bytes_per_file)
            )
        digest = corpus_digest(staging)
        completed = {**expected, "sha256": digest}
        if target.exists():
            shutil.rmtree(target)
        staging.rename(target)
        manifest_tmp = manifest.with_suffix(f"{manifest.suffix}.tmp-{os.getpid()}")
        manifest_tmp.write_text(
            json.dumps(completed, sort_keys=True) + "\n", encoding="utf-8"
        )
        manifest_tmp.replace(manifest)
    finally:
        if staging.exists():
            shutil.rmtree(staging)
    return digest


def _mount_filesystem_from_info(path: pathlib.Path, mountinfo: str) -> str:
    """Resolve the effective filesystem, preferring a real mount over its autofs trigger."""
    best: tuple[int, str] | None = None
    for line in mountinfo.splitlines():
        left, separator, right = line.partition(" - ")
        if not separator:
            continue
        fields = left.split()
        right_fields = right.split()
        if len(fields) < 5 or not right_fields:
            continue
        mountpoint = pathlib.Path(fields[4].replace("\\040", " "))
        try:
            path.relative_to(mountpoint)
        except ValueError:
            continue
        candidate = (len(str(mountpoint)), right_fields[0])
        if best is None or candidate[0] >= best[0]:
            best = candidate
    return best[1] if best else "unknown"


def _mount_filesystem(path: pathlib.Path) -> str:
    """Return the effective Linux mount type for path, or an explicit unknown value."""
    try:
        resolved = path.resolve(strict=True)
        mountinfo = pathlib.Path("/proc/self/mountinfo").read_text(encoding="utf-8")
        return _mount_filesystem_from_info(resolved, mountinfo)
    except (OSError, RuntimeError):
        return "unknown"


def storage(label: str, root: pathlib.Path) -> Storage:
    root.mkdir(parents=True, exist_ok=True)
    stat = root.stat()
    return Storage(label=label, root=root, filesystem=_mount_filesystem(root), device_id=stat.st_dev)


def effective_cores(host: object) -> int:
    """Conservatively derive CPUs available to the benchmark process."""
    values = [value for value in (
        getattr(host, "cores", 0), getattr(host, "affinity_cores", 0)
    ) if isinstance(value, int) and value > 0]
    quota = getattr(host, "cgroup_quota_cores", 0.0)
    if isinstance(quota, (int, float)) and quota > 0:
        values.append(max(1, math.floor(quota)))
    return min(values) if values else 1


def power_points(limit: int, cap: int | None = None) -> tuple[int, ...]:
    """Return powers of two plus the exact effective limit."""
    limit = max(1, min(limit, cap)) if cap is not None else max(1, limit)
    points: list[int] = []
    value = 1
    while value <= limit:
        points.append(value)
        value *= 2
    if points[-1] != limit:
        points.append(limit)
    return tuple(points)


def parse_points(raw: str | None, default: tuple[int, ...]) -> tuple[int, ...]:
    if raw is None:
        return default
    try:
        values = tuple(sorted({int(value) for value in raw.split(",")}))
    except ValueError as exc:
        raise ValueError(
            "scaling points must be positive comma-separated integers"
        ) from exc
    if not values or values[0] != 1:
        raise ValueError(
            "scaling points must be positive comma-separated integers and include 1"
        )
    return values

@contextlib.contextmanager
def benchmark_cache_directory() -> Iterator[pathlib.Path]:
    """Create an isolated cache under KeyHog's configured-path allowlist."""
    with tempfile.TemporaryDirectory(
        prefix=".keyhog-bench-scaling-cache-", dir=pathlib.Path.home()
    ) as raw:
        yield pathlib.Path(raw)


def _command(
    executable: pathlib.Path,
    corpus: pathlib.Path,
    output: pathlib.Path,
    cache_dir: pathlib.Path,
    backend: str,
    threads: int,
    reader_threads: int,
) -> list[str]:
    command = [
        str(executable), "scan", str(corpus),
        "--format", "json-envelope", "--output", str(output),
        "--no-config", "--no-default-excludes", "--quiet",
        "--daemon=off", "--backend", backend,
        "--cache-dir", str(cache_dir), "--threads", str(threads),
    ]
    if reader_threads > 0:
        command.extend(("--reader-threads", str(reader_threads)))
    return command


def page_cache_policy(panel: str) -> str:
    """Name the page-cache state used by one measurement panel."""
    if panel == "threads":
        return "warm"
    if hasattr(os, "posix_fadvise") and hasattr(os, "POSIX_FADV_DONTNEED"):
        return "evicted-posix-fadvise"
    return "warm-platform-no-eviction-api"


def evict_corpus_pages(root: pathlib.Path) -> None:
    """Ask the kernel to evict clean corpus pages before an I/O-sensitive run."""
    if page_cache_policy("storage") != "evicted-posix-fadvise":
        return
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        descriptor = os.open(path, os.O_RDONLY)
        try:
            os.posix_fadvise(descriptor, 0, 0, os.POSIX_FADV_DONTNEED)
        except OSError as exc:
            raise RuntimeError(
                f"cannot evict client page-cache bytes for scaling corpus {path}: {exc}"
            ) from exc
        finally:
            os.close(descriptor)


def _run_process(
    command: list[str],
    output: pathlib.Path,
    pass_fds: tuple[int, ...],
    runner: Callable[..., tuple[str, str, object]] = run_measured,
) -> Trial:
    _stdout, stderr, stats = runner(command, timeout=1800, pass_fds=pass_fds)
    if stats.timed_out or stats.exit_code not in KeyhogScanner.success_exit_codes:
        detail = stderr.strip().splitlines()[-1] if stderr.strip() else "no stderr"
        raise RuntimeError(
            f"scaling scan failed with exit {stats.exit_code}"
            f"{' after timeout' if stats.timed_out else ''}: {detail}"
        )
    findings = KeyhogScanner._parse(output, config_id="readme-scaling")
    if findings:
        raise RuntimeError(
            f"deterministic scaling corpus produced {len(findings)} findings; "
            "the workload must stay finding-free"
        )
    return Trial(
        wall_ms=stats.wall_ms,
        peak_rss_kb=stats.peak_rss_kb,
        max_process_rss_kb=stats.peak_rss_kb,
        exit_codes=(stats.exit_code,),
        finding_count=0,
    )


def run_case(
    case: Case,
    *,
    executable: pathlib.Path,
    pass_fds: tuple[int, ...],
    roots: dict[str, pathlib.Path],
    cache_dir: pathlib.Path,
    backend: str,
    output_root: pathlib.Path,
    runner: Callable[..., tuple[str, str, object]] = run_measured,
) -> Trial:
    """Measure one case; partition cases execute independent scans concurrently."""
    commands: list[tuple[list[str], pathlib.Path]] = []
    for index in range(case.processes):
        corpus = roots[case.storage] / case.workload
        if case.processes > 1:
            corpus = roots[case.storage] / f"partition-{index}" / case.workload
        if page_cache_policy(case.panel) == "evicted-posix-fadvise":
            evict_corpus_pages(corpus)
        output = output_root / f"{case.panel}-{case.label}-{index}.json"
        commands.append((
            _command(
                executable, corpus, output, cache_dir, backend,
                case.threads_per_process, case.reader_threads,
            ),
            output,
        ))

    started = time.perf_counter()
    if len(commands) == 1:
        return _run_process(commands[0][0], commands[0][1], pass_fds, runner)
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(commands)) as pool:
        futures = [
            pool.submit(_run_process, command, output, pass_fds, runner)
            for command, output in commands
        ]
        trials = [future.result() for future in futures]
    wall_ms = (time.perf_counter() - started) * 1000.0
    return Trial(
        wall_ms=wall_ms,
        peak_rss_kb=sum(trial.peak_rss_kb for trial in trials),
        max_process_rss_kb=max(trial.peak_rss_kb for trial in trials),
        exit_codes=tuple(code for trial in trials for code in trial.exit_codes),
        finding_count=sum(trial.finding_count for trial in trials),
    )


def _cases(
    workloads: Sequence[Workload],
    storages: Sequence[Storage],
    cores: int,
    thread_points: tuple[int, ...],
    reader_points: tuple[int, ...],
    partition_points: tuple[int, ...],
) -> list[Case]:
    by_name = {workload.name: workload for workload in workloads}
    primary = storages[0]
    medium = by_name["medium"]
    small = by_name["small"]
    cases: list[Case] = []
    for threads in thread_points:
        cases.append(Case(
            "threads", str(threads), primary.label, "medium", 1, threads, 0,
            medium.total_bytes, medium.files,
        ))
    for readers in reader_points:
        cases.append(Case(
            "readers", str(readers), primary.label, "medium", 1, cores, readers,
            medium.total_bytes, medium.files,
        ))
    for workload in workloads:
        cases.append(Case(
            "sizes", workload.name, primary.label, workload.name, 1, cores, 0,
            workload.total_bytes, workload.files,
        ))
    for item in storages:
        cases.append(Case(
            "storage", item.label, item.label, "medium", 1, cores, 0,
            medium.total_bytes, medium.files,
        ))
    for processes in partition_points:
        threads = max(1, cores // processes)
        cases.append(Case(
            "partitions", str(processes), primary.label, "small", processes,
            threads, 0, small.total_bytes * processes, small.files * processes,
        ))
    return cases


def _prepare_all(
    storages: Sequence[Storage], workloads: Sequence[Workload], partition_count: int
) -> tuple[dict[str, pathlib.Path], dict[str, dict[str, str]]]:
    roots = {item.label: item.root for item in storages}
    digests: dict[str, dict[str, str]] = {}
    for item in storages:
        digests[item.label] = {}
        for workload in workloads:
            digests[item.label][workload.name] = prepare_corpus(item.root, workload)
    primary = storages[0]
    small = next(workload for workload in workloads if workload.name == "small")
    for index in range(partition_count):
        partition_root = primary.root / f"partition-{index}"
        digest = prepare_corpus(partition_root, small)
        if digest != digests[primary.label][small.name]:
            raise RuntimeError("partition workload bytes diverged from canonical small corpus")
    return roots, digests


def capture(
    *,
    binary: str,
    storages: Sequence[Storage],
    trials: int,
    warmups: int,
    backend: str,
    source_state: str,
    thread_points: tuple[int, ...] | None = None,
    reader_points: tuple[int, ...] | None = None,
    partition_points: tuple[int, ...] | None = None,
) -> dict[str, object]:
    """Run the complete scaling matrix and return its validated evidence snapshot."""
    if trials < 1 or warmups < 0:
        raise ValueError("trials must be positive and warmups cannot be negative")
    if not storages:
        raise ValueError("at least one storage root is required")
    if source_state not in {"clean", "developer-dirty"}:
        raise ValueError("source_state must be clean or developer-dirty")
    host = hardware.capture()
    cores = effective_cores(host)
    thread_points = thread_points or power_points(cores)
    reader_points = reader_points or power_points(cores)
    partition_points = partition_points or power_points(cores, cap=4)
    workloads = tuple(Workload(*values) for values in DEFAULT_WORKLOADS)
    roots, digests = _prepare_all(storages, workloads, max(partition_points))
    cases = _cases(
        workloads, storages, cores, thread_points, reader_points, partition_points
    )

    with (
        tempfile.TemporaryDirectory(prefix="keyhog-scaling-output-") as temp,
        benchmark_cache_directory() as cache_dir,
    ):
        temp_root = pathlib.Path(temp)
        output_root = temp_root / "output"
        output_root.mkdir()
        with sibling_executable_snapshot(binary) as snapshot:
            version = assert_keyhog_binary_current(
                str(snapshot.launch_path), pass_fds=snapshot.pass_fds
            )
            warm_case = next(case for case in cases if case.panel == "threads")
            for _ in range(warmups):
                run_case(
                    warm_case, executable=snapshot.launch_path,
                    pass_fds=snapshot.pass_fds, roots=roots, cache_dir=cache_dir,
                    backend=backend, output_root=output_root,
                )
            rows = []
            for case in cases:
                samples = [
                    run_case(
                        case, executable=snapshot.launch_path,
                        pass_fds=snapshot.pass_fds, roots=roots,
                        cache_dir=cache_dir, backend=backend,
                        output_root=output_root,
                    ).to_json()
                    for _ in range(trials)
                ]
                rows.append({
                    "panel": case.panel,
                    "label": case.label,
                    "storage": case.storage,
                    "workload": case.workload,
                    "processes": case.processes,
                    "threads_per_process": case.threads_per_process,
                    "reader_threads": case.reader_threads,
                    "total_bytes": case.total_bytes,
                    "total_files": case.total_files,
                    "page_cache": page_cache_policy(case.panel),
                    "trials": samples,
                })

            scanner = KeyhogScanner(binary)
            evidence: dict[str, object] = {
                "schema": SCHEMA,
                "generated_at": dt.datetime.now(dt.timezone.utc).replace(
                    microsecond=0
                ).isoformat().replace("+00:00", "Z"),
                "source_state": source_state,
                "scanner": {
                    "version": version,
                    "executable_sha256": snapshot.sha256,
                    "detector_corpus_sha256": scanner.detector_corpus_sha256(),
                    "backend": backend,
                },
                "host": host.to_json(),
                "effective_cores": cores,
                "warmups": warmups,
                "trial_count": trials,
                "workloads": [
                    workload.to_json(digests[storages[0].label][workload.name])
                    for workload in workloads
                ],
                "storages": [item.to_json() for item in storages],
                "storage_corpus_sha256": digests,
                "rows": rows,
            }
    validate(evidence)
    return evidence


def _require_exact_keys(value: object, keys: set[str], context: str) -> dict:
    if not isinstance(value, dict):
        raise ValueError(f"{context} must be an object")
    actual = set(value)
    if actual != keys:
        raise ValueError(f"{context} fields differ: missing={keys - actual}, unknown={actual - keys}")
    return value


def validate(evidence: object) -> dict[str, object]:
    """Fail closed on incomplete, hand-shaped, or internally inconsistent evidence."""
    root_keys = {
        "schema", "generated_at", "source_state", "scanner", "host",
        "effective_cores", "warmups", "trial_count", "workloads", "storages",
        "storage_corpus_sha256", "rows",
    }
    root = _require_exact_keys(evidence, root_keys, "scaling evidence")
    if root["schema"] != SCHEMA:
        raise ValueError(f"unsupported scaling schema {root['schema']!r}")
    generated_at = root["generated_at"]
    if not isinstance(generated_at, str) or not generated_at.endswith("Z"):
        raise ValueError("scaling generated_at must be a UTC RFC 3339 timestamp")
    try:
        dt.datetime.fromisoformat(generated_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(
            "scaling generated_at must be a UTC RFC 3339 timestamp"
        ) from exc
    if root["source_state"] not in {"clean", "developer-dirty"}:
        raise ValueError("scaling source_state is invalid")
    if type(root["effective_cores"]) is not int or root["effective_cores"] < 1:
        raise ValueError("effective_cores must be positive")
    if type(root["warmups"]) is not int or root["warmups"] < 0:
        raise ValueError("warmups cannot be negative")
    if type(root["trial_count"]) is not int or root["trial_count"] < 1:
        raise ValueError("trial_count must be positive")

    scanner = _require_exact_keys(
        root["scanner"],
        {"version", "executable_sha256", "detector_corpus_sha256", "backend"},
        "scanner",
    )
    if any(
        not isinstance(scanner[field], str) or not scanner[field].strip()
        for field in ("version", "backend")
    ):
        raise ValueError("scanner version and backend must be nonempty strings")
    for digest_name in ("executable_sha256", "detector_corpus_sha256"):
        digest = scanner[digest_name]
        if (
            not isinstance(digest, str)
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
        ):
            raise ValueError(f"scanner {digest_name} must be lowercase SHA-256")

    _require_exact_keys(
        root["host"], set(Host.__dataclass_fields__), "host"
    )
    workloads = root["workloads"]
    if not isinstance(workloads, list):
        raise ValueError("scaling workloads must be a list")
    workload_keys = {
        "name", "files", "bytes_per_file", "total_bytes", "sha256",
    }
    workload_by_name: dict[str, dict] = {}
    for index, workload_value in enumerate(workloads):
        workload = _require_exact_keys(
            workload_value, workload_keys, f"workload {index}"
        )
        name = workload["name"]
        if not isinstance(name, str) or not name:
            raise ValueError(f"workload {index} name must be nonempty")
        if name in workload_by_name:
            raise ValueError(f"duplicate scaling workload {name!r}")
        if any(
            type(workload[field]) is not int or workload[field] < 1
            for field in ("files", "bytes_per_file", "total_bytes")
        ):
            raise ValueError(f"workload {name!r} has invalid size fields")
        if workload["total_bytes"] != workload["files"] * workload["bytes_per_file"]:
            raise ValueError(f"workload {name!r} total bytes do not multiply exactly")
        digest = workload["sha256"]
        if (
            not isinstance(digest, str)
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
        ):
            raise ValueError(f"workload {name!r} digest must be lowercase SHA-256")
        workload_by_name[name] = workload
    if list(workload_by_name) != ["small", "medium", "large"]:
        raise ValueError(
            "scaling workloads must contain ordered small, medium, and large"
        )

    storages = root["storages"]
    if not isinstance(storages, list) or not storages:
        raise ValueError("scaling storages cannot be empty")
    storage_keys = {"label", "filesystem", "device_id"}
    storage_labels: list[str] = []
    for index, storage_value in enumerate(storages):
        storage_row = _require_exact_keys(
            storage_value, storage_keys, f"storage {index}"
        )
        label = storage_row["label"]
        if not isinstance(label, str) or not label or label in storage_labels:
            raise ValueError(f"storage {index} has an invalid or duplicate label")
        if not isinstance(storage_row["filesystem"], str) or not storage_row["filesystem"]:
            raise ValueError(f"storage {label!r} filesystem must be nonempty")
        if type(storage_row["device_id"]) is not int or storage_row["device_id"] < 0:
            raise ValueError(f"storage {label!r} device ID must be nonnegative")
        storage_labels.append(label)

    storage_digests = _require_exact_keys(
        root["storage_corpus_sha256"], set(storage_labels), "storage corpus digests"
    )
    for label in storage_labels:
        copies = _require_exact_keys(
            storage_digests[label], set(workload_by_name),
            f"storage {label!r} corpus digests",
        )
        for name, workload in workload_by_name.items():
            if copies[name] != workload["sha256"]:
                raise ValueError(
                    f"storage {label!r} workload {name!r} bytes differ from canonical"
                )

    rows = root["rows"]
    required_panels = {"threads", "readers", "sizes", "storage", "partitions"}
    if not isinstance(rows, list):
        raise ValueError("scaling rows must be a list")
    row_keys = {
        "panel", "label", "storage", "workload", "processes",
        "threads_per_process", "reader_threads", "total_bytes", "total_files",
        "page_cache", "trials",
    }
    trial_keys = {
        "wall_ms", "peak_rss_kb", "max_process_rss_kb", "exit_codes",
        "finding_count",
    }
    panels: dict[str, list[dict]] = {panel: [] for panel in required_panels}
    for index, row_value in enumerate(rows):
        row = _require_exact_keys(row_value, row_keys, f"row {index}")
        panel = row["panel"]
        if panel not in required_panels:
            raise ValueError(f"row {index} uses unknown panel {panel!r}")
        panels[panel].append(row)
        if row["storage"] not in storage_labels:
            raise ValueError(f"row {index} refers to unknown storage")
        workload = workload_by_name.get(row["workload"])
        if workload is None:
            raise ValueError(f"row {index} refers to unknown workload")
        if any(
            type(row[field]) is not int or row[field] < 1
            for field in (
                "processes", "threads_per_process", "total_bytes", "total_files",
            )
        ):
            raise ValueError(f"row {index} has invalid positive integer fields")
        if type(row["reader_threads"]) is not int or row["reader_threads"] < 0:
            raise ValueError(f"row {index} has invalid reader_threads")
        if (
            row["total_bytes"] != workload["total_bytes"] * row["processes"]
            or row["total_files"] != workload["files"] * row["processes"]
        ):
            raise ValueError(f"row {index} totals do not match its exact workload")
        valid_cache = (
            row["page_cache"] == "warm"
            if panel == "threads"
            else row["page_cache"] in {
                "evicted-posix-fadvise", "warm-platform-no-eviction-api",
            }
        )
        if not valid_cache:
            raise ValueError(f"row {index} page-cache policy is invalid")
        samples = row["trials"]
        if not isinstance(samples, list) or len(samples) != root["trial_count"]:
            raise ValueError(f"row {index} trial count does not match evidence")
        for trial_index, trial_value in enumerate(samples):
            trial = _require_exact_keys(
                trial_value, trial_keys, f"row {index} trial {trial_index}"
            )
            wall = trial["wall_ms"]
            if (
                isinstance(wall, bool)
                or not isinstance(wall, (int, float))
                or not math.isfinite(wall)
                or wall <= 0
            ):
                raise ValueError(f"row {index} has invalid wall time")
            for rss_field in ("peak_rss_kb", "max_process_rss_kb"):
                if type(trial[rss_field]) is not int or trial[rss_field] < 0:
                    raise ValueError(f"row {index} has invalid {rss_field}")
            if trial["max_process_rss_kb"] > trial["peak_rss_kb"]:
                raise ValueError(f"row {index} process RSS exceeds summed RSS")
            if trial["finding_count"] != 0:
                raise ValueError(f"row {index} scaling corpus was not finding-free")
            exit_codes = trial["exit_codes"]
            if (
                not isinstance(exit_codes, list)
                or len(exit_codes) != row["processes"]
                or any(
                    type(code) is not int
                    or code not in KeyhogScanner.success_exit_codes
                    for code in exit_codes
                )
            ):
                raise ValueError(f"row {index} has invalid process exit codes")

    for panel, panel_rows in panels.items():
        if not panel_rows:
            raise ValueError(f"scaling rows are missing panel {panel!r}")
        labels = [row["label"] for row in panel_rows]
        if len(labels) != len(set(labels)):
            raise ValueError(f"scaling panel {panel!r} has duplicate labels")
    io_cache_policies = {
        row["page_cache"]
        for panel in ("readers", "sizes", "storage", "partitions")
        for row in panels[panel]
    }
    if len(io_cache_policies) != 1:
        raise ValueError("I/O-sensitive panels must share one page-cache policy")
    if [row["label"] for row in panels["sizes"]] != ["small", "medium", "large"]:
        raise ValueError("size rows must be ordered small, medium, and large")
    if [row["label"] for row in panels["storage"]] != storage_labels:
        raise ValueError("storage rows must match the declared storage order")
    for panel in ("threads", "readers", "partitions"):
        try:
            points = [int(row["label"]) for row in panels[panel]]
        except (TypeError, ValueError) as exc:
            raise ValueError(f"scaling panel {panel!r} labels must be integers") from exc
        if points[0] != 1 or points != sorted(set(points)):
            raise ValueError(
                f"scaling panel {panel!r} must start at 1 and increase uniquely"
            )

    primary = storage_labels[0]
    for row in panels["threads"]:
        if (
            row["storage"] != primary
            or row["workload"] != "medium"
            or row["processes"] != 1
            or row["threads_per_process"] != int(row["label"])
            or row["reader_threads"] != 0
        ):
            raise ValueError("thread scaling row axes are inconsistent")
    for row in panels["readers"]:
        if (
            row["storage"] != primary
            or row["workload"] != "medium"
            or row["processes"] != 1
            or row["threads_per_process"] != root["effective_cores"]
            or row["reader_threads"] != int(row["label"])
        ):
            raise ValueError("reader scaling row axes are inconsistent")
    for row in panels["sizes"]:
        if (
            row["storage"] != primary
            or row["workload"] != row["label"]
            or row["processes"] != 1
            or row["threads_per_process"] != root["effective_cores"]
            or row["reader_threads"] != 0
        ):
            raise ValueError("corpus-size scaling row axes are inconsistent")
    for row in panels["storage"]:
        if (
            row["storage"] != row["label"]
            or row["workload"] != "medium"
            or row["processes"] != 1
            or row["threads_per_process"] != root["effective_cores"]
            or row["reader_threads"] != 0
        ):
            raise ValueError("storage scaling row axes are inconsistent")
    for row in panels["partitions"]:
        processes = int(row["label"])
        if (
            row["storage"] != primary
            or row["workload"] != "small"
            or row["processes"] != processes
            or row["threads_per_process"] != max(
                1, root["effective_cores"] // processes
            )
            or row["reader_threads"] != 0
        ):
            raise ValueError("partition scaling row axes are inconsistent")
    return root


def load(path: pathlib.Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read scaling evidence {path}: {exc}") from exc
    return validate(value)


def _median(values: Sequence[float]) -> float:
    return statistics.median(values)


def _p95(values: Sequence[float]) -> float:
    ordered = sorted(values)
    return ordered[max(0, math.ceil(len(ordered) * 0.95) - 1)]


def _metrics(row: dict) -> dict[str, float]:
    walls = [trial["wall_ms"] for trial in row["trials"]]
    rss = [trial["peak_rss_kb"] for trial in row["trials"]]
    wall = _median(walls)
    return {
        "wall_ms": wall,
        "p95_ms": _p95(walls),
        "throughput": row["total_bytes"] / (1024 * 1024) / (wall / 1000),
        "rss_mb": _median(rss) / 1024,
        "rss_max_mb": max(rss) / 1024,
    }


def _fmt_bytes(value: int) -> str:
    return f"{value / (1024 * 1024):,.0f} MiB"


def render(evidence: object) -> str:
    root = validate(evidence)
    rows = root["rows"]
    panels = {name: [row for row in rows if row["panel"] == name] for name in (
        "threads", "readers", "sizes", "storage", "partitions"
    )}
    host = root["host"]
    scanner = root["scanner"]
    lines = [
        BEGIN,
        "### CPU, reader, storage, size, and partition scaling",
        "",
        (
            f"Generated by `make -C benchmarks readme-scaling` from "
            f"`benchmarks/reports/readme-scaling.json`. The harness ran "
            f"{root['trial_count']} measured trial(s) after {root['warmups']} warm-up(s) "
            f"with explicit `{scanner['backend']}` and daemon routing off. "
            "Worker scaling uses a warm client page cache to isolate CPU work. "
            "Reader, corpus-size, storage, and partition rows request clean-page "
            "eviction with `posix_fadvise` where the platform supports it; the "
            "snapshot records the policy on every row. "
            "Every workload is byte-deterministic and finding-free."
        ),
        "",
        (
            f"Host: `{host.get('cpu', 'unknown')}`, {root['effective_cores']} effective "
            f"logical cores, {host.get('ram_mb', 0):,} MiB RAM, "
            f"`{host.get('os', 'unknown')}`. Evidence: `{root['source_state']}`, "
            f"binary `{scanner['executable_sha256'][:12]}`."
        ),
        "",
        "#### Scan worker scaling",
        "",
        "| Workers | Reader threads | Median wall | p95 wall | Throughput | Speedup | Efficiency | Median peak RSS |",
        "|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    thread_base = _metrics(panels["threads"][0])["wall_ms"]
    for row in panels["threads"]:
        metric = _metrics(row)
        speedup = thread_base / metric["wall_ms"]
        lines.append(
            f"| {row['threads_per_process']} | auto | {metric['wall_ms']:,.1f} ms | "
            f"{metric['p95_ms']:,.1f} ms | {metric['throughput']:,.1f} MiB/s | "
            f"{speedup:.2f}x | {speedup / row['threads_per_process'] * 100:.1f}% | "
            f"{metric['rss_mb']:,.1f} MiB |"
        )

    lines.extend((
        "",
        "#### Filesystem reader scaling",
        "",
        "| Scan workers | Reader threads | Median wall | p95 wall | Throughput | Relative to 1 reader | Median peak RSS |",
        "|---:|---:|---:|---:|---:|---:|---:|",
    ))
    reader_base = _metrics(panels["readers"][0])["wall_ms"]
    for row in panels["readers"]:
        metric = _metrics(row)
        lines.append(
            f"| {row['threads_per_process']} | {row['reader_threads']} | "
            f"{metric['wall_ms']:,.1f} ms | {metric['p95_ms']:,.1f} ms | "
            f"{metric['throughput']:,.1f} MiB/s | {reader_base / metric['wall_ms']:.2f}x | "
            f"{metric['rss_mb']:,.1f} MiB |"
        )

    lines.extend((
        "",
        "#### Corpus-size scaling",
        "",
        "| Corpus | Files | Exact bytes | Median wall | p95 wall | Throughput | Median peak RSS |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ))
    for row in panels["sizes"]:
        metric = _metrics(row)
        lines.append(
            f"| {row['workload']} | {row['total_files']:,} | {_fmt_bytes(row['total_bytes'])} | "
            f"{metric['wall_ms']:,.1f} ms | {metric['p95_ms']:,.1f} ms | "
            f"{metric['throughput']:,.1f} MiB/s | {metric['rss_mb']:,.1f} MiB |"
        )

    storage_by_label = {item["label"]: item for item in root["storages"]}
    lines.extend((
        "",
        "#### Storage scaling",
        "",
        "| Storage class | Filesystem | Device ID | Median wall | p95 wall | Throughput | Relative to first storage | Median peak RSS |",
        "|---|---|---:|---:|---:|---:|---:|---:|",
    ))
    storage_base = _metrics(panels["storage"][0])["wall_ms"]
    for row in panels["storage"]:
        metric = _metrics(row)
        item = storage_by_label[row["storage"]]
        lines.append(
            f"| {item['label']} | `{item['filesystem']}` | `{item['device_id']}` | "
            f"{metric['wall_ms']:,.1f} ms | {metric['p95_ms']:,.1f} ms | "
            f"{metric['throughput']:,.1f} MiB/s | {storage_base / metric['wall_ms']:.2f}x | "
            f"{metric['rss_mb']:,.1f} MiB |"
        )

    lines.extend((
        "",
        "#### Concurrent partition scaling",
        "",
        "| Processes | Workers per process | Aggregate workers | Total files | Total bytes | Median wall | Aggregate throughput | Speedup | Median summed peak RSS |",
        "|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ))
    partition_base_metric = _metrics(panels["partitions"][0])
    base_rate_per_process = partition_base_metric["throughput"]
    for row in panels["partitions"]:
        metric = _metrics(row)
        lines.append(
            f"| {row['processes']} | {row['threads_per_process']} | "
            f"{row['processes'] * row['threads_per_process']} | {row['total_files']:,} | "
            f"{_fmt_bytes(row['total_bytes'])} | {metric['wall_ms']:,.1f} ms | "
            f"{metric['throughput']:,.1f} MiB/s | {metric['throughput'] / base_rate_per_process:.2f}x | "
            f"{metric['rss_mb']:,.1f} MiB |"
        )
    lines.extend((
        "",
        "These rows are measurements, not universal tuning constants. Run the generator on the target host and storage. Use the knee where throughput stops improving, then reserve CPU and memory for the CI runner or orchestration layer.",
        END,
    ))
    return "\n".join(lines)


def update_readme(readme: pathlib.Path, rendered: str, *, check: bool) -> None:
    text = readme.read_text(encoding="utf-8")
    if BEGIN not in text or END not in text:
        raise ValueError(f"{readme} is missing the scaling benchmark markers")
    before, remainder = text.split(BEGIN, 1)
    _old, after = remainder.split(END, 1)
    updated = before + rendered + after
    if check:
        if updated != text:
            raise ValueError(
                f"{readme} scaling tables are stale; run `make -C benchmarks readme-scaling`"
            )
        return
    readme.write_text(updated, encoding="utf-8")


def _storage_arg(value: str) -> tuple[str, pathlib.Path]:
    label, separator, raw_path = value.partition("=")
    if not separator or not label or not raw_path:
        raise argparse.ArgumentTypeError("storage must be LABEL=PATH")
    return label, pathlib.Path(raw_path)


@contextlib.contextmanager
def _default_storages(
    workspace_root: pathlib.Path,
    supplied: Sequence[tuple[str, pathlib.Path]],
) -> Iterator[list[Storage]]:
    if supplied:
        yield [storage(label, path) for label, path in supplied]
        return
    workspace = storage("workspace", workspace_root)
    with tempfile.TemporaryDirectory(prefix="keyhog-scaling-local-") as temp:
        local = storage("local-temp", pathlib.Path(temp))
        items = [workspace]
        if local.device_id != workspace.device_id or local.filesystem != workspace.filesystem:
            items.append(local)
        yield items


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    measure = sub.add_parser("measure", help="measure and write the full scaling matrix")
    measure.add_argument("--binary")
    measure.add_argument("--snapshot", type=pathlib.Path, required=True)
    measure.add_argument("--readme", type=pathlib.Path)
    measure.add_argument("--markdown", type=pathlib.Path)
    measure.add_argument("--workspace-root", type=pathlib.Path, required=True)
    measure.add_argument("--storage", action="append", type=_storage_arg, default=[])
    measure.add_argument("--trials", type=int, default=3)
    measure.add_argument("--warmups", type=int, default=1)
    measure.add_argument("--backend", default="simd")
    measure.add_argument("--source-state", required=True, choices=("clean", "developer-dirty"))
    measure.add_argument("--thread-points")
    measure.add_argument("--reader-points")
    measure.add_argument("--partition-points")
    check = sub.add_parser("check", help="validate evidence and generated README bytes")
    check.add_argument("--snapshot", type=pathlib.Path, required=True)
    check.add_argument("--readme", type=pathlib.Path, required=True)
    render_command = sub.add_parser("render", help="render evidence as Markdown")
    render_command.add_argument("--snapshot", type=pathlib.Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "measure":
        binary = args.binary or resolve_keyhog_binary()
        if not binary:
            raise SystemExit("KeyHog binary not found; pass --binary or set KEYHOG_BIN")
        with _default_storages(args.workspace_root, args.storage) as storages:
            host = hardware.capture()
            cores = effective_cores(host)
            evidence = capture(
                binary=binary,
                storages=storages,
                trials=args.trials,
                warmups=args.warmups,
                backend=args.backend,
                source_state=args.source_state,
                thread_points=parse_points(args.thread_points, power_points(cores)),
                reader_points=parse_points(args.reader_points, power_points(cores)),
                partition_points=parse_points(
                    args.partition_points, power_points(cores, cap=4)
                ),
            )
        args.snapshot.parent.mkdir(parents=True, exist_ok=True)
        args.snapshot.write_text(
            json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        rendered = render(evidence)
        if args.markdown:
            args.markdown.parent.mkdir(parents=True, exist_ok=True)
            args.markdown.write_text(rendered + "\n", encoding="utf-8")
        if args.readme:
            update_readme(args.readme, rendered, check=False)
        elif not args.markdown:
            print(rendered)
        return 0
    evidence = load(args.snapshot)
    rendered = render(evidence)
    if args.command == "check":
        update_readme(args.readme, rendered, check=True)
    else:
        print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
