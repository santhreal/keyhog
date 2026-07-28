"""Fail-closed evidence contract for GitHub-hosted CPU benchmark results.

``context`` creates a private read-only workload snapshot before measurement and
binds it to the checked-out source, release binary, detector corpus, reviewed
policy, exact GitHub run and effective CPU allocation. ``gate`` is result-only:
it accepts no self-authored notion of "current" and requires trusted run/UTC
inputs from the workflow invocation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import pathlib
import re
import shutil
import stat
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping, Sequence

from . import SCHEMA_VERSION
from .corpora.base import Corpus
from .executable_snapshot import sha256_file
from .hardware import (
    ACCELERATOR_INVENTORY_OBSERVED,
    ACCELERATOR_INVENTORY_UNAVAILABLE,
    CGROUP_QUOTA_UNBOUNDED,
    accelerator_inventory as capture_accelerator_inventory,
    capture as capture_host,
)
from .keyhog_version import (
    KeyhogVersionError,
    assert_workspace_tracked_tree_clean,
    workspace_detector_corpus_sha256,
    workspace_git_hash,
)
from .runner import resolve_corpus_with_root
from .schema import CONF_BINS, HostedBinding, RunResult, is_sha256

POLICY_SCHEMA = "hosted-cpu-policy-v2"
CONTEXT_SCHEMA = "hosted-cpu-context-v2"
PARITY_SCHEMA = "cpu-simd-unicode-parity-v2"
_COMMIT_RE = re.compile(r"(?m)^Commit:\s+([0-9a-f]{40}(?:[0-9a-f]{24})?)\s*$")
_GIT_COMMIT_RE = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?")


class HostedCpuInputError(ValueError):
    """Evidence inputs cannot produce a trustworthy verdict."""


@dataclass(frozen=True)
class TrustedRun:
    now: datetime
    policy_sha256: str
    repository: str
    workflow_ref: str
    workflow_sha: str
    run_id: str
    run_attempt: str
    job: str


@dataclass(frozen=True)
class CategoryPolicy:
    name: str
    positives: int
    min_recall: float


@dataclass(frozen=True)
class WorkloadPolicy:
    name: str
    fixture_count: int | None
    labeled_positives: int
    bytes: int | None
    workload_sha256: str | None
    revision: str


@dataclass(frozen=True)
class RowPolicy:
    id: str
    path: str
    corpus: str
    config: Mapping[str, str]
    min_recall: float
    max_wall_ms: float
    min_throughput_mib_s: float
    max_peak_rss_kb: int
    scan_manifest_sha256: str | None
    categories: tuple[CategoryPolicy, ...] = ()

    @property
    def config_id(self) -> str:
        return (
            f"{self.config['backend']}-"
            f"{'cache' if self.config['cache'] == 'on' else 'nocache'}-"
            f"{'daemon' if self.config['daemon'] == 'on' else 'nodaemon'}-"
            f"{self.config['mode']}"
        )


@dataclass(frozen=True)
class HostedCpuPolicy:
    profile: str
    workflow: str
    repository: str
    workflow_file: str
    job: str
    runner_os: str
    runner_arch: str
    runner_environment: str
    effective_cores: int
    min_ram_mb: int
    max_ram_mb: int
    max_evidence_seconds: int
    cuda_visible_devices: str
    nvidia_visible_devices: str
    parity_source_sha256: str
    parity_vector_sha256: str
    parity_detector_examples: int
    supply: Mapping[str, object]
    calibration: Mapping[str, object]
    workloads: Mapping[str, WorkloadPolicy]
    rows: tuple[RowPolicy, ...]


_POLICY_KEYS = {"schema_version", "authority", "runner", "supply", "calibration", "workloads", "rows"}
_AUTHORITY_KEYS = {
    "repository", "workflow_file", "job", "parity_source_sha256",
    "parity_vector_sha256", "parity_detector_examples",
}
_RUNNER_KEYS = {
    "profile", "workflow", "os", "arch", "environment", "effective_cores",
    "min_ram_mb", "max_ram_mb", "max_evidence_seconds",
    "cuda_visible_devices", "nvidia_visible_devices",
}
_SUPPLY_POLICY_KEYS = {
    "runner_image_version", "cpython", "go", "libhyperscan_dev",
    "libhyperscan_runtime", "pkg_config", "libhs_runtime_sha256",
}
_CALIBRATION_KEYS = {
    "status", "thresholds_sha256", "source", "measured_at", "sample_count",
    "statistic", "units", "rationale",
}
_WORKLOAD_KEYS = {
    "fixture_count", "labeled_positives", "bytes", "workload_sha256", "revision",
}
_ROW_KEYS = {
    "id", "path", "corpus", "config", "min_recall", "max_wall_ms",
    "min_throughput_mib_s", "max_peak_rss_kb", "scan_manifest_sha256", "categories",
}
_CONFIG_KEYS = {"backend", "cache", "daemon", "mode"}
_CATEGORY_KEYS = {"name", "positives", "min_recall"}
_CONTEXT_KEYS = {
    "schema_version", "generated_at", "policy_sha256", "source_commit",
    "executable_sha256", "detector_corpus_sha256", "runner", "host",
    "accelerator_enforcement", "supply", "immutability", "workloads",
    "category_denominators", "snapshot_roots", "acquisition",
}
_RUNNER_RECEIPT_KEYS = {
    "provider", "profile", "name", "os", "arch", "environment", "workflow",
    "workflow_ref", "workflow_sha", "repository", "run_id", "run_attempt", "job",
}
_ACCELERATOR_ENFORCEMENT_KEYS = {
    "cuda_visible_devices", "nvidia_visible_devices", "route", "inventory",
}
_ACCELERATOR_INVENTORY_KEYS = {"source", "status", "devices"}
_ACCELERATOR_DEVICE_KEYS = {"name", "vram_mb"}
_CPU_ROUTE = "policy-cpu-simd-only"


def _object(value: object, what: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise HostedCpuInputError(f"{what} must be a JSON object")
    return value


def _exact_keys(value: Mapping[str, object], expected: set[str], what: str) -> None:
    missing = sorted(expected - set(value))
    unknown = sorted(set(value) - expected)
    if missing or unknown:
        raise HostedCpuInputError(
            f"{what} keys differ from the contract: missing={missing}, unknown={unknown}"
        )


def _host_cpu_allocation_violations(
    host: Mapping[str, object],
    effective_cores: int,
) -> list[str]:
    """Return exact CPU-allocation violations without coercing unknown quota state."""
    violations: list[str] = []
    for field in ("cores", "affinity_cores"):
        if type(host.get(field)) is not int or host.get(field) != effective_cores:
            violations.append(f"host {field} is not exact {effective_cores}")
    quota = host.get("cgroup_quota_cores")
    if quota == CGROUP_QUOTA_UNBOUNDED:
        if host.get("affinity_cores") != effective_cores:
            violations.append(
                "unbounded cgroup quota requires exact process affinity"
            )
    elif (
        isinstance(quota, bool)
        or not isinstance(quota, (int, float))
        or not math.isfinite(float(quota))
        or float(quota) != float(effective_cores)
    ):
        violations.append(
            "host cgroup quota is neither the exact finite allocation nor "
            f"documented unbounded: observed={quota!r}"
        )
    return violations


def _validate_accelerator_enforcement(
    value: object,
    policy: HostedCpuPolicy,
) -> None:
    """Validate CPU-route controls and the explicitly scoped best-effort inventory."""
    receipt = _object(value, "accelerator enforcement receipt")
    _exact_keys(
        receipt,
        _ACCELERATOR_ENFORCEMENT_KEYS,
        "accelerator enforcement receipt",
    )
    if (
        receipt["cuda_visible_devices"] != policy.cuda_visible_devices
        or receipt["nvidia_visible_devices"] != policy.nvidia_visible_devices
    ):
        raise HostedCpuInputError(
            "accelerator feature environment receipt does not match policy"
        )
    if receipt["route"] != _CPU_ROUTE:
        raise HostedCpuInputError("accelerator route receipt is not CPU/SIMD-only")
    inventory = _object(receipt["inventory"], "accelerator inventory")
    _exact_keys(inventory, _ACCELERATOR_INVENTORY_KEYS, "accelerator inventory")
    if inventory["source"] != "nvidia-smi":
        raise HostedCpuInputError("accelerator inventory source is not nvidia-smi")
    status = inventory["status"]
    if status not in {
        ACCELERATOR_INVENTORY_OBSERVED,
        ACCELERATOR_INVENTORY_UNAVAILABLE,
    }:
        raise HostedCpuInputError("accelerator inventory status is invalid")
    devices = inventory["devices"]
    if not isinstance(devices, list):
        raise HostedCpuInputError("accelerator inventory devices must be a list")
    if status == ACCELERATOR_INVENTORY_UNAVAILABLE and devices:
        raise HostedCpuInputError(
            "unavailable accelerator inventory cannot claim observed devices"
        )
    for device in devices:
        item = _object(device, "accelerator inventory device")
        _exact_keys(item, _ACCELERATOR_DEVICE_KEYS, "accelerator inventory device")
        if not isinstance(item["name"], str) or not item["name"]:
            raise HostedCpuInputError("accelerator inventory device name is missing")
        _strict_int(
            item["vram_mb"],
            "accelerator inventory device vram_mb",
            positive=True,
        )


def _strict_int(value: object, what: str, *, positive: bool = False) -> int:
    if type(value) is not int or value < (1 if positive else 0):
        qualifier = "positive" if positive else "non-negative"
        raise HostedCpuInputError(f"{what} must be a {qualifier} JSON integer")
    return value


def _strict_number(value: object, what: str, *, positive: bool = True) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise HostedCpuInputError(f"{what} must be a finite JSON number")
    number = float(value)
    if not math.isfinite(number) or (positive and number <= 0):
        raise HostedCpuInputError(f"{what} must be finite and positive")
    return number


def _ratio(value: object, what: str, *, allow_zero: bool = False) -> float:
    number = _strict_number(value, what, positive=not allow_zero)
    if number < 0 or number > 1:
        raise HostedCpuInputError(f"{what} must be in {'[0, 1]' if allow_zero else '(0, 1]'}")
    return number


def _optional_int(value: object, what: str) -> int | None:
    return None if value is None else _strict_int(value, what, positive=True)


def _optional_sha(value: object, what: str) -> str | None:
    if value is None:
        return None
    if not is_sha256(value):
        raise HostedCpuInputError(f"{what} must be null or lowercase SHA-256")
    return value


def _json_bytes(value: Mapping[str, object]) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def _canonical_sha(value: object) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(payload).hexdigest()


def policy_sha256(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _threshold_payload(rows: Sequence[Mapping[str, object]]) -> list[dict[str, object]]:
    fields = (
        "id", "corpus", "config", "min_recall", "max_wall_ms",
        "min_throughput_mib_s", "max_peak_rss_kb", "categories",
    )
    return [{field: row[field] for field in fields} for row in rows]


def load_policy(path: pathlib.Path) -> HostedCpuPolicy:
    try:
        raw = _load_json_object(path, "hosted CPU policy")
    except HostedCpuInputError:
        raise
    _exact_keys(raw, _POLICY_KEYS, f"policy {path}")
    if raw["schema_version"] != POLICY_SCHEMA:
        raise HostedCpuInputError(
            f"policy schema {raw['schema_version']!r} != current {POLICY_SCHEMA!r}"
        )
    authority = _object(raw["authority"], "policy authority")
    runner = _object(raw["runner"], "policy runner")
    supply = _object(raw["supply"], "policy supply")
    calibration = _object(raw["calibration"], "policy calibration")
    workloads_raw = _object(raw["workloads"], "policy workloads")
    rows_raw = raw["rows"]
    _exact_keys(authority, _AUTHORITY_KEYS, "policy authority")
    _exact_keys(runner, _RUNNER_KEYS, "policy runner")
    _exact_keys(supply, _SUPPLY_POLICY_KEYS, "policy supply")
    for field in (
        "cpython", "go", "libhyperscan_dev", "libhyperscan_runtime", "pkg_config"
    ):
        if not isinstance(supply[field], str) or not supply[field]:
            raise HostedCpuInputError(f"policy supply {field} must be non-empty")
    for field in ("runner_image_version", "libhs_runtime_sha256"):
        if supply[field] is not None and not is_sha256(supply[field]) and field.endswith("sha256"):
            raise HostedCpuInputError(f"policy supply {field} must be null or SHA-256")
        if field == "runner_image_version" and supply[field] is not None and (
            not isinstance(supply[field], str) or not supply[field]
        ):
            raise HostedCpuInputError("runner_image_version must be null or non-empty")
    _exact_keys(calibration, _CALIBRATION_KEYS, "policy calibration")
    if not isinstance(rows_raw, list) or not rows_raw:
        raise HostedCpuInputError("policy rows must be a non-empty array")
    if calibration["status"] != "unmeasured-release-requirements":
        raise HostedCpuInputError("policy calibration status is unsupported")
    if calibration["measured_at"] is not None or calibration["sample_count"] != 0:
        raise HostedCpuInputError(
            "unmeasured release requirements cannot claim a date or measurement sample"
        )
    if calibration["statistic"] != "none" or not isinstance(calibration["rationale"], str):
        raise HostedCpuInputError("unmeasured calibration provenance is malformed")
    expected_threshold_sha = _canonical_sha(_threshold_payload(rows_raw))
    if calibration["thresholds_sha256"] != expected_threshold_sha:
        raise HostedCpuInputError(
            "policy threshold digest does not bind the configured limits"
        )
    units = calibration["units"]
    if units != {"wall": "ms", "throughput": "MiB/s", "rss": "KiB", "recall": "ratio"}:
        raise HostedCpuInputError("policy calibration units must be explicit canonical units")

    workloads: dict[str, WorkloadPolicy] = {}
    for name, item in workloads_raw.items():
        value = _object(item, f"policy workload {name}")
        _exact_keys(value, _WORKLOAD_KEYS, f"policy workload {name}")
        revision = value["revision"]
        if not isinstance(name, str) or not name or not isinstance(revision, str) or not revision:
            raise HostedCpuInputError("policy workload names/revisions must be non-empty strings")
        workloads[name] = WorkloadPolicy(
            name=name,
            fixture_count=_optional_int(value["fixture_count"], f"{name} fixture_count"),
            labeled_positives=_strict_int(
                value["labeled_positives"], f"{name} labeled_positives", positive=True
            ),
            bytes=_optional_int(value["bytes"], f"{name} bytes"),
            workload_sha256=_optional_sha(value["workload_sha256"], f"{name} workload_sha256"),
            revision=revision,
        )

    rows: list[RowPolicy] = []
    ids: set[str] = set()
    paths: set[str] = set()
    for index, item in enumerate(rows_raw):
        row = _object(item, f"policy rows[{index}]")
        _exact_keys(row, _ROW_KEYS, f"policy rows[{index}]")
        row_id = row["id"]
        if not isinstance(row_id, str) or not row_id or row_id in ids:
            raise HostedCpuInputError(f"policy row id must be non-empty and unique: {row_id!r}")
        result_path = pathlib.PurePosixPath(str(row["path"]))
        if result_path.is_absolute() or ".." in result_path.parts or str(result_path) in paths:
            raise HostedCpuInputError(f"policy row path must be safe and unique: {result_path}")
        corpus = row["corpus"]
        if corpus not in workloads:
            raise HostedCpuInputError(f"policy row {row_id} references unknown workload {corpus!r}")
        config = _object(row["config"], f"row {row_id} config")
        _exact_keys(config, _CONFIG_KEYS, f"row {row_id} config")
        if config["backend"] not in {"cpu", "simd"}:
            raise HostedCpuInputError(f"row {row_id} backend is not explicit CPU/SIMD")
        if config["cache"] != "off" or config["daemon"] != "off":
            raise HostedCpuInputError(f"row {row_id} hosted config must disable cache/daemon")
        if config["mode"] not in {"full", "fast", "deep", "precision"}:
            raise HostedCpuInputError(f"row {row_id} mode is invalid")
        categories_raw = row["categories"]
        if not isinstance(categories_raw, list):
            raise HostedCpuInputError(f"row {row_id} categories must be an array")
        categories: list[CategoryPolicy] = []
        category_names: set[str] = set()
        for category_item in categories_raw:
            category = _object(category_item, f"row {row_id} category")
            _exact_keys(category, _CATEGORY_KEYS, f"row {row_id} category")
            name = category["name"]
            if not isinstance(name, str) or not name or name in category_names:
                raise HostedCpuInputError(f"row {row_id} category names must be unique")
            categories.append(CategoryPolicy(
                name=name,
                positives=_strict_int(category["positives"], f"{row_id}/{name} positives", positive=True),
                min_recall=_ratio(
                    category["min_recall"],
                    f"{row_id}/{name} min_recall",
                    allow_zero=True,
                ),
            ))
            category_names.add(name)
        rows.append(RowPolicy(
            id=row_id,
            path=str(result_path),
            corpus=str(corpus),
            config=dict(config),
            min_recall=_ratio(row["min_recall"], f"row {row_id} min_recall"),
            max_wall_ms=_strict_number(row["max_wall_ms"], f"row {row_id} max_wall_ms"),
            min_throughput_mib_s=_strict_number(
                row["min_throughput_mib_s"], f"row {row_id} min_throughput_mib_s"
            ),
            max_peak_rss_kb=_strict_int(
                row["max_peak_rss_kb"], f"row {row_id} max_peak_rss_kb", positive=True
            ),
            scan_manifest_sha256=_optional_sha(
                row["scan_manifest_sha256"], f"row {row_id} scan_manifest_sha256"
            ),
            categories=tuple(categories),
        ))
        ids.add(row_id)
        paths.add(str(result_path))

    effective_cores = _strict_int(runner["effective_cores"], "runner effective_cores", positive=True)
    min_ram = _strict_int(runner["min_ram_mb"], "runner min_ram_mb", positive=True)
    max_ram = _strict_int(runner["max_ram_mb"], "runner max_ram_mb", positive=True)
    if min_ram > max_ram:
        raise HostedCpuInputError("runner min RAM exceeds max RAM")
    parity_source_sha = authority["parity_source_sha256"]
    if not is_sha256(parity_source_sha):
        raise HostedCpuInputError("authority parity_source_sha256 must be SHA-256")
    parity_vector_sha = authority["parity_vector_sha256"]
    if not is_sha256(parity_vector_sha):
        raise HostedCpuInputError("authority parity_vector_sha256 must be SHA-256")
    return HostedCpuPolicy(
        profile=str(runner["profile"]),
        workflow=str(runner["workflow"]),
        repository=str(authority["repository"]),
        workflow_file=str(authority["workflow_file"]),
        job=str(authority["job"]),
        runner_os=str(runner["os"]),
        runner_arch=str(runner["arch"]),
        runner_environment=str(runner["environment"]),
        effective_cores=effective_cores,
        min_ram_mb=min_ram,
        max_ram_mb=max_ram,
        max_evidence_seconds=_strict_int(
            runner["max_evidence_seconds"], "runner max_evidence_seconds", positive=True
        ),
        cuda_visible_devices=str(runner["cuda_visible_devices"]),
        nvidia_visible_devices=str(runner["nvidia_visible_devices"]),
        parity_source_sha256=parity_source_sha,
        parity_vector_sha256=parity_vector_sha,
        parity_detector_examples=_strict_int(
            authority["parity_detector_examples"], "parity_detector_examples", positive=True
        ),
        supply=dict(supply),
        calibration=dict(calibration),
        workloads=workloads,
        rows=tuple(rows),
    )


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_time(value: object, what: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise HostedCpuInputError(f"{what} must be a timezone-aware ISO-8601 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise HostedCpuInputError(f"{what} is not valid ISO-8601: {value!r}") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise HostedCpuInputError(f"{what} must include a timezone")
    return parsed.astimezone(timezone.utc)


def _runner_from_env(environ: Mapping[str, str]) -> dict[str, str]:
    values = {
        "provider": "github-actions" if environ.get("GITHUB_ACTIONS") == "true" else "",
        "profile": environ.get("KEYHOG_BENCH_RUNNER_PROFILE", ""),
        "name": environ.get("RUNNER_NAME", ""),
        "os": environ.get("RUNNER_OS", ""),
        "arch": environ.get("RUNNER_ARCH", ""),
        "environment": environ.get("RUNNER_ENVIRONMENT", ""),
        "workflow": environ.get("GITHUB_WORKFLOW", ""),
        "workflow_ref": environ.get("GITHUB_WORKFLOW_REF", ""),
        "workflow_sha": environ.get("GITHUB_WORKFLOW_SHA", ""),
        "repository": environ.get("GITHUB_REPOSITORY", ""),
        "run_id": environ.get("GITHUB_RUN_ID", ""),
        "run_attempt": environ.get("GITHUB_RUN_ATTEMPT", ""),
        "job": environ.get("GITHUB_JOB", ""),
    }
    missing = sorted(key for key, value in values.items() if not value)
    if missing:
        raise HostedCpuInputError(f"GitHub runner identity is incomplete: missing={missing}")
    return values


def _corpus_home(corpus: Corpus) -> pathlib.Path:
    if corpus.name == "creddata":
        return corpus.file_root
    return corpus.root


def _copy_snapshot(source: pathlib.Path, destination: pathlib.Path) -> None:
    if destination.exists():
        raise HostedCpuInputError(f"snapshot destination already exists: {destination}")
    if not source.is_dir():
        raise HostedCpuInputError(f"workload source is not a directory: {source}")
    shutil.copytree(
        source,
        destination,
        symlinks=False,
        ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc"),
    )
    for path in sorted(destination.rglob("*"), reverse=True):
        mode = stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH
        if path.is_dir():
            mode |= stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
        path.chmod(mode)
    destination.chmod(stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH |
                      stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def _validate_supply_receipt(
    value: object,
    policy: HostedCpuPolicy,
    *,
    require_external_pins: bool,
) -> list[str]:
    violations: list[str] = []
    try:
        receipt = _object(value, "hosted supply receipt")
        _exact_keys(
            receipt,
            {
                "schema_version", "runner_image", "cpython", "go", "apt",
                "libhs_runtime",
            },
            "hosted supply receipt",
        )
        if receipt["schema_version"] != "hosted-cpu-supply-v1":
            raise HostedCpuInputError("hosted supply schema is not current")
        image = _object(receipt["runner_image"], "runner image")
        _exact_keys(image, {"label", "os", "version"}, "runner image")
        if image["label"] != "ubuntu-24.04" or not all(
            isinstance(image[field], str) and image[field]
            for field in ("os", "version")
        ):
            raise HostedCpuInputError("runner image identity is incomplete")
        for name in ("cpython", "go"):
            item = _object(receipt[name], f"supply {name}")
            _exact_keys(item, {"requested", "observed"}, f"supply {name}")
            if item["requested"] != policy.supply[name] or item["observed"] != policy.supply[name]:
                raise HostedCpuInputError(f"supply {name} differs from policy")
        apt = _object(receipt["apt"], "supply apt")
        _exact_keys(
            apt,
            {"libhyperscan-dev", "libhyperscan5", "pkg-config"},
            "supply apt",
        )
        expected_apt = {
            "libhyperscan-dev": policy.supply["libhyperscan_dev"],
            "libhyperscan5": policy.supply["libhyperscan_runtime"],
            "pkg-config": policy.supply["pkg_config"],
        }
        if apt != expected_apt:
            raise HostedCpuInputError("apt supply versions differ from policy")
        libhs = _object(receipt["libhs_runtime"], "libhs runtime")
        _exact_keys(
            libhs,
            {"path", "sha256", "package", "package_version"},
            "libhs runtime",
        )
        if (
            not pathlib.Path(str(libhs["path"])).is_absolute()
            or not is_sha256(libhs["sha256"])
            or libhs["package"] != "libhyperscan5"
            or libhs["package_version"] != policy.supply["libhyperscan_runtime"]
        ):
            raise HostedCpuInputError("libhs runtime identity is malformed")
        if require_external_pins:
            if policy.supply["runner_image_version"] is None:
                violations.append("runner image version policy is uncalibrated; fresh pin required")
            elif image["version"] != policy.supply["runner_image_version"]:
                violations.append("runner image version differs from policy")
            if policy.supply["libhs_runtime_sha256"] is None:
                violations.append("libhs runtime digest policy is uncalibrated; fresh pin required")
            elif libhs["sha256"] != policy.supply["libhs_runtime_sha256"]:
                violations.append("libhs runtime digest differs from policy")
    except HostedCpuInputError as exc:
        violations.append(str(exc))
    return violations


def _validate_immutability_receipt(
    value: object,
    snapshot_roots: object,
) -> list[str]:
    violations: list[str] = []
    try:
        receipt = _object(value, "immutability receipt")
        _exact_keys(
            receipt,
            {
                "schema_version", "snapshot_root", "owner", "mount_options",
                "write_probe", "interval_end",
            },
            "immutability receipt",
        )
        if receipt["schema_version"] != "hosted-cpu-immutability-v1":
            raise HostedCpuInputError("immutability receipt schema is not current")
        root = pathlib.Path(str(receipt["snapshot_root"]))
        if not root.is_absolute():
            raise HostedCpuInputError("immutability snapshot root is not absolute")
        if not isinstance(snapshot_roots, dict) or any(
            pathlib.Path(str(path)).parent != root for path in snapshot_roots.values()
        ):
            raise HostedCpuInputError("immutability root does not own all workload snapshots")
        options = receipt["mount_options"]
        if (
            receipt["owner"] != "root:root"
            or receipt["write_probe"] != "rejected"
            or receipt["interval_end"] != "post-publication cleanup"
            or not isinstance(options, list)
            or "ro" not in options
        ):
            raise HostedCpuInputError("snapshot interval is not root-owned read-only")
    except HostedCpuInputError as exc:
        violations.append(str(exc))
    return violations


def capture_context(
    policy_path: pathlib.Path,
    source_commit: str,
    binary: pathlib.Path,
    workloads: Sequence[str],
    *,
    repo_root: pathlib.Path,
    snapshot_root: pathlib.Path,
    environ: Mapping[str, str] | None = None,
    generated_at: str | None = None,
) -> dict[str, object]:
    """Capture source/run identity and immutable private workload snapshots."""
    policy = load_policy(policy_path)
    env = os.environ if environ is None else environ
    if _GIT_COMMIT_RE.fullmatch(source_commit) is None:
        raise HostedCpuInputError("source_commit must be a full lowercase Git commit")
    try:
        current_commit = workspace_git_hash(repo_root)
        assert_workspace_tracked_tree_clean(repo_root)
        detector_sha = workspace_detector_corpus_sha256(repo_root)
        executable_sha = sha256_file(binary.resolve(strict=True))
    except (KeyhogVersionError, OSError) as exc:
        raise HostedCpuInputError(f"cannot capture current source identity: {exc}") from exc
    if current_commit != source_commit:
        raise HostedCpuInputError(
            f"source commit mismatch: requested={source_commit}, workspace={current_commit}"
        )
    runner = _runner_from_env(env)
    expected_runner = {
        "profile": policy.profile,
        "workflow": policy.workflow,
        "os": policy.runner_os,
        "arch": policy.runner_arch,
        "environment": policy.runner_environment,
        "repository": policy.repository,
        "job": policy.job,
        "workflow_sha": source_commit,
    }
    for field, expected in expected_runner.items():
        if runner[field] != expected:
            raise HostedCpuInputError(
                f"wrong runner {field}: {runner[field]!r}, expected={expected!r}"
            )
    expected_ref_prefix = f"{policy.repository}/{policy.workflow_file}@"
    if not runner["workflow_ref"].startswith(expected_ref_prefix):
        raise HostedCpuInputError("workflow_ref does not name the policy-owned workflow")
    if env.get("CUDA_VISIBLE_DEVICES") != policy.cuda_visible_devices or env.get(
        "NVIDIA_VISIBLE_DEVICES"
    ) != policy.nvidia_visible_devices:
        raise HostedCpuInputError(
            "accelerator feature environment receipt does not match policy"
        )
    host = capture_host()
    allocation_violations = _host_cpu_allocation_violations(
        host.to_json(),
        policy.effective_cores,
    )
    if allocation_violations:
        raise HostedCpuInputError(
            "effective CPU allocation is not the exact policy class: "
            + "; ".join(allocation_violations)
        )
    if not policy.min_ram_mb <= host.ram_mb <= policy.max_ram_mb:
        raise HostedCpuInputError("runner RAM is outside the policy class")
    inventory = capture_accelerator_inventory()
    supply_path = env.get("KEYHOG_BENCH_SUPPLY_RECEIPT")
    if not supply_path:
        raise HostedCpuInputError("KEYHOG_BENCH_SUPPLY_RECEIPT is required")
    supply_receipt = _load_json_object(
        pathlib.Path(supply_path),
        "hosted CPU supply receipt",
    )
    supply_violations = _validate_supply_receipt(
        supply_receipt,
        policy,
        require_external_pins=False,
    )
    if supply_violations:
        raise HostedCpuInputError("; ".join(supply_violations))

    expected_names = set(policy.workloads)
    if set(workloads) != expected_names or len(workloads) != len(expected_names):
        raise HostedCpuInputError(
            f"context workloads must exactly match policy: {sorted(expected_names)}"
        )
    snapshot_root = snapshot_root.resolve()
    snapshot_root.mkdir(parents=True, exist_ok=False)
    workload_info: dict[str, dict[str, object]] = {}
    category_denominators: dict[str, dict[str, int]] = {}
    roots: dict[str, str] = {}
    acquisition: dict[str, dict[str, object]] = {}
    for name in sorted(workloads):
        source_corpus = resolve_corpus_with_root(name, None)
        source_info = source_corpus.info()
        destination = snapshot_root / name
        _copy_snapshot(_corpus_home(source_corpus).resolve(strict=True), destination)
        snapshot_corpus = resolve_corpus_with_root(name, destination)
        snapshot_info = snapshot_corpus.info()
        if snapshot_info != source_info:
            raise HostedCpuInputError(f"{name} snapshot differs from its source workload")
        workload_info[name] = snapshot_info.to_json()
        categories: dict[str, int] = {}
        for record in snapshot_corpus.records():
            if record.label:
                categories[record.category] = categories.get(record.category, 0) + 1
        if sum(categories.values()) != snapshot_info.labeled_positives:
            raise HostedCpuInputError(
                f"{name} category denominators do not conserve labeled positives"
            )
        category_denominators[name] = dict(sorted(categories.items()))
        roots[name] = str(destination)
        acquisition[name] = {
            "revision": policy.workloads[name].revision,
            "source_root_sha256": source_info.workload_sha256,
            "snapshot_root_sha256": snapshot_info.workload_sha256,
        }
    stamp = generated_at or _utc_now()
    _parse_time(stamp, "context generated_at")
    return {
        "schema_version": CONTEXT_SCHEMA,
        "generated_at": stamp,
        "policy_sha256": policy_sha256(policy_path),
        "source_commit": source_commit,
        "executable_sha256": executable_sha,
        "detector_corpus_sha256": detector_sha,
        "runner": runner,
        "host": host.to_json(),
        "accelerator_enforcement": {
            "cuda_visible_devices": env.get("CUDA_VISIBLE_DEVICES"),
            "nvidia_visible_devices": env.get("NVIDIA_VISIBLE_DEVICES"),
            "route": _CPU_ROUTE,
            "inventory": inventory,
        },
        "supply": supply_receipt,
        "immutability": None,
        "workloads": workload_info,
        "category_denominators": category_denominators,
        "snapshot_roots": roots,
        "acquisition": acquisition,
    }


def write_context(value: Mapping[str, object], output: pathlib.Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(_json_bytes(value))


def _reject_json_constant(value: str) -> object:
    raise HostedCpuInputError(f"non-finite JSON constant {value!r} is forbidden")


def _load_json_object(path: pathlib.Path, what: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(), parse_constant=_reject_json_constant)
    except (OSError, json.JSONDecodeError, TypeError, ValueError, OverflowError) as exc:
        if isinstance(exc, HostedCpuInputError):
            raise
        raise HostedCpuInputError(f"cannot load {what} {path}: {exc}") from exc
    return _object(value, f"{what} {path}")


def _version_commit(version: str) -> str:
    match = _COMMIT_RE.search(version)
    return match.group(1) if match else ""


def _strict_outcome(raw: object, what: str) -> tuple[int, int, int]:
    value = _object(raw, what)
    _exact_keys(value, {"tp", "fp", "fn", "precision", "recall", "f1"}, what)
    tp = _strict_int(value["tp"], f"{what}.tp")
    fp = _strict_int(value["fp"], f"{what}.fp")
    fn = _strict_int(value["fn"], f"{what}.fn")
    denominator = tp + fn
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / denominator if denominator else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    expected = {"precision": precision, "recall": recall, "f1": f1}
    for field, number in expected.items():
        observed = _strict_number(value[field], f"{what}.{field}", positive=False)
        if abs(observed - round(number, 4)) > 0.00005:
            raise HostedCpuInputError(f"{what}.{field} is inconsistent with tp/fp/fn")
    return tp, fp, fn


def _strict_detector_stat(raw: object, what: str) -> None:
    value = _object(raw, what)
    _exact_keys(
        value,
        {"tp", "fp", "unique_tp", "precision", "tp_hist", "fp_hist"},
        what,
    )
    tp = _strict_int(value["tp"], f"{what}.tp")
    fp = _strict_int(value["fp"], f"{what}.fp")
    unique_tp = _strict_int(value["unique_tp"], f"{what}.unique_tp")
    if unique_tp > tp:
        raise HostedCpuInputError(f"{what}.unique_tp exceeds tp")
    expected_precision = tp / (tp + fp) if tp + fp else 0.0
    observed_precision = _strict_number(
        value["precision"], f"{what}.precision", positive=False
    )
    if abs(observed_precision - round(expected_precision, 4)) > 0.00005:
        raise HostedCpuInputError(f"{what}.precision is inconsistent with tp/fp")
    for field in ("tp_hist", "fp_hist"):
        histogram = value[field]
        if not isinstance(histogram, list) or len(histogram) != CONF_BINS:
            raise HostedCpuInputError(f"{what}.{field} must have {CONF_BINS} bins")
        for index, count in enumerate(histogram):
            _strict_int(count, f"{what}.{field}[{index}]")


def _validate_raw_result(raw: Mapping[str, object], requirement: RowPolicy) -> None:
    _exact_keys(
        raw,
        {
            "schema_version", "generated_at", "host", "scanner", "corpus",
            "detection", "speed", "finding_count", "exit_code", "timed_out",
            "available", "error", "scan_manifest", "static_recovery", "bloom",
            "hosted_binding",
        },
        f"{requirement.id} result",
    )
    scanner = _object(raw.get("scanner"), f"{requirement.id} scanner")
    _exact_keys(
        scanner,
        {
            "name", "version", "config_id", "config", "executable_sha256",
            "detector_corpus_sha256", "execution_route",
        },
        f"{requirement.id} scanner",
    )
    config = _object(scanner.get("config"), f"{requirement.id} config")
    _exact_keys(config, _CONFIG_KEYS, f"{requirement.id} config")
    if config != dict(requirement.config):
        raise HostedCpuInputError(f"{requirement.id} complete config differs from policy")
    if scanner.get("config_id") != requirement.config_id:
        raise HostedCpuInputError(f"{requirement.id} config_id is inconsistent")
    for field in ("daemon_pid", "daemon_requests"):
        if field in scanner:
            _strict_int(scanner[field], f"{requirement.id} scanner.{field}")
    corpus = _object(raw.get("corpus"), f"{requirement.id} corpus")
    _exact_keys(corpus, {"name", "fixture_count", "labeled_positives", "bytes", "workload_sha256"}, f"{requirement.id} corpus")
    for field in ("fixture_count", "labeled_positives", "bytes"):
        _strict_int(corpus[field], f"{requirement.id} corpus.{field}", positive=True)
    if not is_sha256(corpus["workload_sha256"]):
        raise HostedCpuInputError(f"{requirement.id} workload digest is malformed")
    speed = _object(raw.get("speed"), f"{requirement.id} speed")
    _exact_keys(speed, {"wall_ms", "throughput_mb_s", "peak_rss_kb"}, f"{requirement.id} speed")
    _strict_number(speed["wall_ms"], f"{requirement.id} wall_ms")
    _strict_number(speed["throughput_mb_s"], f"{requirement.id} throughput_mib_s")
    _strict_int(speed["peak_rss_kb"], f"{requirement.id} peak_rss_kb", positive=True)
    if type(raw.get("available")) is not bool or raw.get("available") is not True:
        raise HostedCpuInputError(f"{requirement.id} available must be true")
    if type(raw.get("timed_out")) is not bool or raw.get("timed_out") is not False:
        raise HostedCpuInputError(f"{requirement.id} timed_out must be false")
    exit_code = _strict_int(raw.get("exit_code"), f"{requirement.id} exit_code")
    if exit_code not in {0, 1, 10}:
        raise HostedCpuInputError(f"{requirement.id} exit_code {exit_code} is not a KeyHog success")
    if raw.get("error") != "":
        raise HostedCpuInputError(f"{requirement.id} error must be empty")
    _strict_int(raw.get("finding_count"), f"{requirement.id} finding_count", positive=True)
    detection = _object(raw.get("detection"), f"{requirement.id} detection")
    _exact_keys(
        detection,
        {"overall", "per_category", "per_detector"},
        f"{requirement.id} detection",
    )
    overall = _strict_outcome(detection.get("overall"), f"{requirement.id} overall")
    categories = _object(detection.get("per_category"), f"{requirement.id} per_category")
    for name, outcome in categories.items():
        if not isinstance(name, str) or not name:
            raise HostedCpuInputError(f"{requirement.id} category name is invalid")
        _strict_outcome(outcome, f"{requirement.id}/{name}")
    per_detector = _object(detection.get("per_detector"), f"{requirement.id} per_detector")
    for name, outcome in per_detector.items():
        if not isinstance(name, str) or not name:
            raise HostedCpuInputError(f"{requirement.id} detector name is invalid")
        _strict_detector_stat(outcome, f"{requirement.id}/detector/{name}")
    if overall[0] + overall[2] != corpus["labeled_positives"]:
        raise HostedCpuInputError(f"{requirement.id} overall recall denominator is impossible")
    binding = raw.get("hosted_binding")
    HostedBinding.from_json(binding)


def _context_violations(
    policy: HostedCpuPolicy,
    expected_policy_sha: str,
    context: Mapping[str, object],
    trusted: TrustedRun,
) -> list[str]:
    violations: list[str] = []
    try:
        _exact_keys(context, _CONTEXT_KEYS, "hosted context")
    except HostedCpuInputError as exc:
        violations.append(str(exc))
    if context.get("schema_version") != CONTEXT_SCHEMA:
        violations.append(f"context schema is not {CONTEXT_SCHEMA!r}")
    if expected_policy_sha != trusted.policy_sha256 or context.get("policy_sha256") != trusted.policy_sha256:
        violations.append("reviewed policy SHA-256 does not match workflow/context")
    if context.get("source_commit") != trusted.workflow_sha:
        violations.append("context source commit does not match trusted workflow SHA")
    for field in ("executable_sha256", "detector_corpus_sha256"):
        if not is_sha256(context.get(field)):
            violations.append(f"context {field} is missing or malformed")
    try:
        generated = _parse_time(context.get("generated_at"), "context generated_at")
        if generated > trusted.now + timedelta(minutes=1):
            violations.append("context timestamp is in the future")
        if trusted.now - generated > timedelta(seconds=policy.max_evidence_seconds):
            violations.append("context is stale relative to trusted current UTC")
    except HostedCpuInputError as exc:
        violations.append(str(exc))
    runner = context.get("runner")
    if not isinstance(runner, dict):
        violations.append("context runner receipt is missing")
    else:
        try:
            _exact_keys(runner, _RUNNER_RECEIPT_KEYS, "context runner")
        except HostedCpuInputError as exc:
            violations.append(str(exc))
        if not isinstance(runner.get("name"), str) or not runner["name"]:
            violations.append("context runner name is missing")
        expected = {
            "provider": "github-actions", "profile": policy.profile,
            "workflow": policy.workflow, "os": policy.runner_os,
            "arch": policy.runner_arch, "environment": policy.runner_environment,
            "repository": trusted.repository, "workflow_ref": trusted.workflow_ref,
            "workflow_sha": trusted.workflow_sha, "run_id": trusted.run_id,
            "run_attempt": trusted.run_attempt, "job": trusted.job,
        }
        for field, value in expected.items():
            if runner.get(field) != value:
                violations.append(f"wrong trusted runner {field}")
    if trusted.repository != policy.repository or trusted.job != policy.job:
        violations.append("trusted run authority differs from policy")
    if not trusted.workflow_ref.startswith(f"{policy.repository}/{policy.workflow_file}@"):
        violations.append("trusted workflow_ref differs from policy workflow file")
    if trusted.workflow_sha != context.get("source_commit"):
        violations.append("trusted workflow SHA/source binding failed")
    host = context.get("host")
    if not isinstance(host, dict):
        violations.append("context host receipt is missing")
    else:
        try:
            _exact_keys(
                host,
                {
                    "hostname_hash", "os", "kernel", "cpu", "cores",
                    "affinity_cores", "cgroup_quota_cores", "ram_mb", "gpu",
                    "gpu_vram_mb",
                },
                "context host",
            )
        except HostedCpuInputError as exc:
            violations.append(str(exc))
        violations.extend(
            _host_cpu_allocation_violations(host, policy.effective_cores)
        )
        ram = host.get("ram_mb")
        if type(ram) is not int or not policy.min_ram_mb <= ram <= policy.max_ram_mb:
            violations.append("host RAM differs from runner class")
        if not isinstance(host.get("gpu"), str):
            violations.append("host GPU observation must be a string")
        gpu_vram = host.get("gpu_vram_mb")
        if type(gpu_vram) is not int or gpu_vram < 0:
            violations.append("host GPU VRAM observation must be non-negative")
    try:
        _validate_accelerator_enforcement(
            context.get("accelerator_enforcement"),
            policy,
        )
    except HostedCpuInputError as exc:
        violations.append(str(exc))
    violations.extend(
        _validate_supply_receipt(
            context.get("supply"),
            policy,
            require_external_pins=True,
        )
    )
    workloads = context.get("workloads")
    category_denominators = context.get("category_denominators")
    roots = context.get("snapshot_roots")
    acquisition = context.get("acquisition")
    if not isinstance(workloads, dict) or set(workloads) != set(policy.workloads):
        violations.append("context workload set differs from policy")
    if (
        not isinstance(category_denominators, dict)
        or set(category_denominators) != set(policy.workloads)
    ):
        violations.append("context category denominator set differs from policy workloads")
    if not isinstance(roots, dict) or set(roots) != set(policy.workloads):
        violations.append("context snapshot roots differ from policy")
    if not isinstance(acquisition, dict) or set(acquisition) != set(policy.workloads):
        violations.append("context acquisition set differs from policy")
    violations.extend(
        _validate_immutability_receipt(
            context.get("immutability"),
            roots,
        )
    )
    if isinstance(roots, dict):
        resolved_roots: list[pathlib.Path] = []
        for name, value in roots.items():
            if not isinstance(value, str) or not value:
                violations.append(f"{name} snapshot root is missing")
                continue
            path = pathlib.Path(value)
            if not path.is_absolute():
                violations.append(f"{name} snapshot root is not absolute")
            resolved_roots.append(path)
        if len(set(resolved_roots)) != len(resolved_roots):
            violations.append("workloads do not have distinct snapshot roots")
    if isinstance(workloads, dict):
        for name, expected in policy.workloads.items():
            value = workloads.get(name)
            if not isinstance(value, dict):
                continue
            try:
                _exact_keys(value, {"name", "fixture_count", "labeled_positives", "bytes", "workload_sha256"}, f"context workload {name}")
                for field in ("fixture_count", "labeled_positives", "bytes"):
                    _strict_int(value[field], f"context {name}.{field}", positive=True)
            except HostedCpuInputError as exc:
                violations.append(str(exc))
                continue
            if value.get("name") != name or value.get("labeled_positives") != expected.labeled_positives:
                violations.append(f"{name} workload labels differ from policy")
            if expected.fixture_count is None or expected.bytes is None or expected.workload_sha256 is None:
                violations.append(f"{name} workload policy is uncalibrated; fresh pin required")
            else:
                if value.get("fixture_count") != expected.fixture_count:
                    violations.append(f"{name} fixture count differs from approved workload")
                if value.get("bytes") != expected.bytes:
                    violations.append(f"{name} byte count differs from approved workload")
                if value.get("workload_sha256") != expected.workload_sha256:
                    violations.append(f"{name} digest differs from approved workload")
            if isinstance(category_denominators, dict):
                denominators = category_denominators.get(name)
                if not isinstance(denominators, dict) or not denominators:
                    violations.append(f"{name} category denominators are missing")
                else:
                    total = 0
                    for category_name, count in denominators.items():
                        if not isinstance(category_name, str) or not category_name:
                            violations.append(f"{name} category name is invalid")
                            continue
                        try:
                            total += _strict_int(
                                count,
                                f"context {name}/{category_name} denominator",
                                positive=True,
                            )
                        except HostedCpuInputError as exc:
                            violations.append(str(exc))
                    if total != value.get("labeled_positives"):
                        violations.append(
                            f"{name} category denominators do not conserve labels"
                        )
            if isinstance(acquisition, dict):
                acquired = acquisition.get(name)
                if not isinstance(acquired, dict):
                    violations.append(f"{name} acquisition receipt is missing")
                else:
                    try:
                        _exact_keys(
                            acquired,
                            {"revision", "source_root_sha256", "snapshot_root_sha256"},
                            f"{name} acquisition",
                        )
                    except HostedCpuInputError as exc:
                        violations.append(str(exc))
                    if acquired.get("revision") != expected.revision:
                        violations.append(f"{name} acquisition revision differs from policy")
                    if (
                        acquired.get("source_root_sha256") != value.get("workload_sha256")
                        or acquired.get("snapshot_root_sha256") != value.get("workload_sha256")
                    ):
                        violations.append(f"{name} snapshot acquisition digest is inconsistent")
    return violations


def _parity_violations(
    policy: HostedCpuPolicy,
    context: Mapping[str, object],
    parity: Mapping[str, object],
    trusted: TrustedRun,
    context_sha256: str,
) -> list[str]:
    expected_keys = {
        "schema_version", "generated_at", "source_commit", "detector_corpus_sha256",
        "policy_sha256", "context_sha256", "repository", "workflow_ref",
        "workflow_sha", "run_id", "run_attempt", "job", "release_executable_sha256",
        "test_executable_sha256", "parity_source_sha256", "vector_sha256",
        "detector_examples", "unicode_divergences", "command",
    }
    violations: list[str] = []
    try:
        _exact_keys(parity, expected_keys, "Unicode parity receipt")
    except HostedCpuInputError as exc:
        violations.append(str(exc))
    if parity.get("schema_version") != PARITY_SCHEMA:
        violations.append("Unicode parity schema is not current")
    expected = {
        "source_commit": context.get("source_commit"),
        "detector_corpus_sha256": context.get("detector_corpus_sha256"),
        "policy_sha256": trusted.policy_sha256,
        "context_sha256": context_sha256,
        "repository": trusted.repository,
        "workflow_ref": trusted.workflow_ref,
        "workflow_sha": trusted.workflow_sha,
        "run_id": trusted.run_id,
        "run_attempt": trusted.run_attempt,
        "job": trusted.job,
        "release_executable_sha256": context.get("executable_sha256"),
        "parity_source_sha256": policy.parity_source_sha256,
        "vector_sha256": policy.parity_vector_sha256,
        "detector_examples": policy.parity_detector_examples,
        "unicode_divergences": 0,
    }
    for field, value in expected.items():
        if parity.get(field) != value:
            violations.append(f"Unicode parity {field} differs from trusted context/policy")
    if not is_sha256(parity.get("test_executable_sha256")):
        violations.append("Unicode parity test_executable_sha256 is malformed")
    command = parity.get("command")
    if (
        not isinstance(command, list)
        or len(command) != 2
        or not all(isinstance(item, str) and item for item in command)
        or command[1] != "--nocapture"
    ):
        violations.append("Unicode parity command is malformed")
    else:
        try:
            observed_test_sha = sha256_file(pathlib.Path(command[0]).resolve(strict=True))
            if observed_test_sha != parity.get("test_executable_sha256"):
                violations.append("Unicode parity test_executable_sha256 differs from executed artifact")
        except OSError:
            violations.append("Unicode parity test executable is unavailable")
    try:
        generated = _parse_time(parity.get("generated_at"), "Unicode parity generated_at")
        context_time = _parse_time(context.get("generated_at"), "context generated_at")
        if generated < context_time or generated > trusted.now + timedelta(minutes=1):
            violations.append("Unicode parity timestamp is outside current run")
    except HostedCpuInputError as exc:
        violations.append(str(exc))
    return violations


def validate_evidence(
    policy: HostedCpuPolicy,
    policy_path: pathlib.Path,
    context: Mapping[str, object],
    parity: Mapping[str, object],
    root: pathlib.Path,
    *,
    trusted: TrustedRun,
    context_sha256: str,
) -> list[str]:
    """Return deterministic violations for already-produced current-run evidence."""
    expected_policy_sha = policy_sha256(policy_path)
    violations = _context_violations(policy, expected_policy_sha, context, trusted)
    violations.extend(_parity_violations(policy, context, parity, trusted, context_sha256))
    try:
        context_time = _parse_time(context.get("generated_at"), "context generated_at")
    except HostedCpuInputError:
        context_time = trusted.now
    deadline = context_time + timedelta(seconds=policy.max_evidence_seconds)
    host = context.get("host")
    workloads = context.get("workloads")
    category_denominators = context.get("category_denominators")

    expected_binding = {
        "context_sha256": context_sha256,
        "repository": trusted.repository,
        "workflow_ref": trusted.workflow_ref,
        "workflow_sha": trusted.workflow_sha,
        "run_id": trusted.run_id,
        "run_attempt": trusted.run_attempt,
        "job": trusted.job,
    }
    for requirement in policy.rows:
        path = root / pathlib.PurePosixPath(requirement.path)
        try:
            raw = _load_json_object(path, f"result {requirement.id}")
            _validate_raw_result(raw, requirement)
            row = RunResult.from_json(raw, source=str(path))
        except (HostedCpuInputError, ValueError, TypeError, OverflowError) as exc:
            violations.append(f"{requirement.id}: {exc}")
            continue
        prefix = f"{requirement.id}:"
        if row.schema_version != SCHEMA_VERSION:
            violations.append(f"{prefix} schema is not current")
        if row.host.to_json() != host:
            violations.append(f"{prefix} host differs from current run context")
        if row.hosted_binding is None or row.hosted_binding.to_json() != expected_binding:
            violations.append(f"{prefix} hosted run/context binding differs")
        if row.scanner.name != "keyhog":
            violations.append(f"{prefix} scanner is not keyhog")
        if row.scanner.execution_route != "in_process" or row.scanner.daemon_pid or row.scanner.daemon_requests:
            violations.append(f"{prefix} execution route is not in-process CPU")
        if _version_commit(row.scanner.version) != trusted.workflow_sha:
            violations.append(f"{prefix} source commit differs from trusted workflow SHA")
        if row.scanner.executable_sha256 != context.get("executable_sha256"):
            violations.append(f"{prefix} executable digest differs from context")
        if row.scanner.detector_corpus_sha256 != context.get("detector_corpus_sha256"):
            violations.append(f"{prefix} detector digest differs from context")
        expected_workload = workloads.get(requirement.corpus) if isinstance(workloads, dict) else None
        if not isinstance(expected_workload, dict) or row.corpus.to_json() != expected_workload:
            violations.append(f"{prefix} exact workload differs from pre-run snapshot")
        manifest = row.scan_manifest
        if not isinstance(manifest, dict) or set(manifest) != {"schema_version", "preset", "effective", "overrides"}:
            violations.append(f"{prefix} resolved scan manifest is incomplete")
        else:
            if type(manifest["schema_version"]) is not int or manifest["schema_version"] != 1:
                violations.append(f"{prefix} scan manifest schema is invalid")
            effective = manifest["effective"]
            overrides = manifest["overrides"]
            if not isinstance(effective, dict) or not effective or any(
                not isinstance(k, str) or not isinstance(v, str) for k, v in effective.items()
            ):
                violations.append(f"{prefix} effective scan policy is malformed")
            if not isinstance(overrides, list) or any(not isinstance(v, str) for v in overrides) or len(set(overrides)) != len(overrides):
                violations.append(f"{prefix} scan overrides are malformed")
            manifest_sha = _canonical_sha(manifest)
            if requirement.scan_manifest_sha256 is None:
                violations.append(f"{prefix} scan manifest policy is uncalibrated; fresh pin required")
            elif manifest_sha != requirement.scan_manifest_sha256:
                violations.append(f"{prefix} complete resolved scan manifest differs from policy")
        try:
            generated = _parse_time(row.generated_at, f"{requirement.id} generated_at")
            if generated < context_time or generated > deadline or generated > trusted.now + timedelta(minutes=1):
                violations.append(f"{prefix} result is stale/outside current-run UTC window")
        except HostedCpuInputError as exc:
            violations.append(f"{prefix} {exc}")

        overall = row.detection.overall
        denominator = overall.tp + overall.fn
        expected_positive = policy.workloads[requirement.corpus].labeled_positives
        if denominator != expected_positive:
            violations.append(f"{prefix} overall denominator {denominator} != {expected_positive}")
        recall = overall.recall()
        if recall < requirement.min_recall:
            violations.append(f"{prefix} recall {recall:.6f} < floor {requirement.min_recall:.6f}")
        authenticated_categories = (
            category_denominators.get(requirement.corpus)
            if isinstance(category_denominators, dict)
            else None
        )
        if not isinstance(authenticated_categories, dict) or not authenticated_categories:
            authenticated_categories = {}
        policy_categories = {
            category.name: category for category in requirement.categories
        }
        if policy_categories and (
            set(policy_categories) != set(authenticated_categories)
            or any(
                policy_categories[name].positives != authenticated_categories.get(name)
                for name in policy_categories
            )
        ):
            violations.append(
                f"{prefix} policy category denominators differ from authenticated workload"
            )
        observed_categories = row.detection.per_category
        missing_categories = set(authenticated_categories) - set(observed_categories)
        unexpected_truth_categories = {
            name
            for name, outcome in observed_categories.items()
            if name not in authenticated_categories and outcome.tp + outcome.fn != 0
        }
        if missing_categories or unexpected_truth_categories:
            violations.append(
                f"{prefix} scorer categories differ from authenticated workload: "
                f"missing={sorted(missing_categories)}, "
                f"unexpected={sorted(unexpected_truth_categories)}"
            )
        category_tp = 0
        category_fn = 0
        category_fp = 0
        for name, outcome in observed_categories.items():
            category_fp += outcome.fp
            if name not in authenticated_categories:
                continue
            expected_count = authenticated_categories[name]
            cat_denominator = outcome.tp + outcome.fn
            if cat_denominator != expected_count:
                violations.append(
                    f"{prefix} {name} denominator {cat_denominator} != {expected_count}"
                )
            policy_category = policy_categories.get(name)
            if (
                policy_category is not None
                and outcome.recall() < policy_category.min_recall
            ):
                violations.append(
                    f"{prefix} {name} recall {outcome.recall():.6f} "
                    f"< floor {policy_category.min_recall:.6f}"
                )
            category_tp += outcome.tp
            category_fn += outcome.fn
        if (
            category_tp != overall.tp
            or category_fn != overall.fn
            or category_fp != overall.fp
            or category_tp + category_fn != expected_positive
        ):
            violations.append(f"{prefix} category totals do not conserve overall counts")

        if row.speed.wall_ms > requirement.max_wall_ms:
            violations.append(f"{prefix} wall time exceeds ceiling")
        expected_throughput = (row.corpus.bytes / 1_048_576.0) / (row.speed.wall_ms / 1000.0)
        if abs(row.speed.throughput_mb_s - expected_throughput) > 0.00011:
            violations.append(f"{prefix} throughput is not derived from bound bytes/wall")
        if row.speed.throughput_mb_s < requirement.min_throughput_mib_s:
            violations.append(f"{prefix} throughput is below MiB/s floor")
        if row.speed.peak_rss_kb > requirement.max_peak_rss_kb:
            violations.append(f"{prefix} peak RSS exceeds ceiling")
    return violations


def _trusted_from_args(args: argparse.Namespace) -> TrustedRun:
    now = _parse_time(args.trusted_now, "trusted current UTC")
    if not is_sha256(args.policy_sha256):
        raise HostedCpuInputError("--policy-sha256 must be lowercase SHA-256")
    if _GIT_COMMIT_RE.fullmatch(args.workflow_sha) is None:
        raise HostedCpuInputError("--workflow-sha must be a full Git commit")
    for name in ("repository", "workflow_ref", "run_id", "run_attempt", "job"):
        if not getattr(args, name):
            raise HostedCpuInputError(f"--{name.replace('_', '-')} is required")
    return TrustedRun(
        now=now,
        policy_sha256=args.policy_sha256,
        repository=args.repository,
        workflow_ref=args.workflow_ref,
        workflow_sha=args.workflow_sha,
        run_id=args.run_id,
        run_attempt=args.run_attempt,
        job=args.job,
    )


def run_gate(
    policy_path: pathlib.Path,
    context_path: pathlib.Path,
    parity_path: pathlib.Path,
    root: pathlib.Path,
    *,
    trusted: TrustedRun,
) -> int:
    try:
        policy = load_policy(policy_path)
        context_raw = context_path.read_bytes()
        context = _object(
            json.loads(context_raw, parse_constant=_reject_json_constant), "hosted context"
        )
        parity = _load_json_object(parity_path, "Unicode parity receipt")
        violations = validate_evidence(
            policy, policy_path, context, parity, root,
            trusted=trusted,
            context_sha256=hashlib.sha256(context_raw).hexdigest(),
        )
    except (OSError, json.JSONDecodeError, HostedCpuInputError, TypeError, ValueError, OverflowError) as exc:
        print(f"HOSTED CPU GATE UNDECIDABLE: {exc}", file=sys.stderr)
        return 2
    if violations:
        print(f"HOSTED CPU GATE FAILED ({len(violations)} violation(s)):", file=sys.stderr)
        for violation in violations:
            print(f"  - {violation}", file=sys.stderr)
        return 1
    print(
        f"HOSTED CPU GATE PASSED: profile={policy.profile}, rows={len(policy.rows)}",
        file=sys.stderr,
    )
    return 0


def _main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    context = commands.add_parser("context", help="capture pre-measurement identity")
    context.add_argument("--policy", required=True, type=pathlib.Path)
    context.add_argument("--source-commit", required=True)
    context.add_argument("--binary", required=True, type=pathlib.Path)
    context.add_argument("--repo-root", type=pathlib.Path, default=pathlib.Path(".."))
    context.add_argument("--snapshot-root", required=True, type=pathlib.Path)
    context.add_argument("--workload", action="append", required=True)
    context.add_argument("--output", required=True, type=pathlib.Path)
    gate = commands.add_parser("gate", help="validate existing result evidence only")
    gate.add_argument("--policy", required=True, type=pathlib.Path)
    gate.add_argument("--policy-sha256", required=True)
    gate.add_argument("--context", required=True, type=pathlib.Path)
    gate.add_argument("--unicode-parity", required=True, type=pathlib.Path)
    gate.add_argument("--root", type=pathlib.Path, default=pathlib.Path("."))
    gate.add_argument("--trusted-now", required=True)
    gate.add_argument("--repository", required=True)
    gate.add_argument("--workflow-ref", required=True)
    gate.add_argument("--workflow-sha", required=True)
    gate.add_argument("--run-id", required=True)
    gate.add_argument("--run-attempt", required=True)
    gate.add_argument("--job", required=True)
    args = parser.parse_args(argv)
    if args.command == "context":
        try:
            value = capture_context(
                args.policy, args.source_commit, args.binary, args.workload,
                repo_root=args.repo_root, snapshot_root=args.snapshot_root,
            )
            write_context(value, args.output)
        except (HostedCpuInputError, OSError) as exc:
            print(f"HOSTED CPU CONTEXT FAILED: {exc}", file=sys.stderr)
            return 2
        print(f"wrote hosted CPU context to {args.output}", file=sys.stderr)
        return 0
    try:
        trusted = _trusted_from_args(args)
    except HostedCpuInputError as exc:
        print(f"HOSTED CPU GATE UNDECIDABLE: {exc}", file=sys.stderr)
        return 2
    return run_gate(args.policy, args.context, args.unicode_parity, args.root, trusted=trusted)


if __name__ == "__main__":
    raise SystemExit(_main())
