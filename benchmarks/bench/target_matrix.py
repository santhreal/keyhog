"""Strict hardware and software identities for reproducible performance gates."""

from __future__ import annotations

import hashlib
import json
import pathlib
import tomllib
from dataclasses import dataclass

TARGET_SCHEMA_VERSION = 1
ALLOWED_OSES = frozenset({"linux", "macos", "windows"})
ALLOWED_ARCHES = frozenset({"x86_64", "aarch64"})
ALLOWED_IDENTITY_MODES = frozenset({"exact", "runner-image", "constrained"})
ALLOWED_BACKENDS = frozenset(
    {"auto", "cpu", "simd", "gpu-cuda", "gpu-wgpu", "gpu-metal"}
)
REQUIRED_TARGET_IDS = frozenset(
    {
        "linux-x86_64-rtx5090",
        "macos-arm64-m4-pro",
        "linux-x86_64-hosted-four-core",
        "windows-x86_64-laptop",
    }
)


class TargetMatrixError(ValueError):
    """A target identity that is incomplete, ambiguous, or stale."""


@dataclass(frozen=True)
class SoftwareIdentity:
    """Exact toolchain and runtime versions defining comparable evidence."""

    workspace_version: str
    rustc: str
    python: str
    vyre: str
    hyperscan: str
    workload_catalog: str
    fixture_lock: str


@dataclass(frozen=True)
class TargetIdentity:
    """One exact host or constrained release lane."""

    target_id: str
    os: str
    arch: str
    target_class: str
    identity_mode: str
    cpu: str
    logical_cores: int
    min_ram_mb: int
    gpu: str
    min_gpu_vram_mb: int
    gpu_driver: str
    required_backends: tuple[str, ...]
    evidence: str


@dataclass(frozen=True)
class TargetMatrix:
    """Validated software identity and complete target host set."""

    schema_version: int
    software: SoftwareIdentity
    targets: tuple[TargetIdentity, ...]


def _text(value: object, field: str) -> str:
    """Validate and return non-empty stripped string from target matrix."""
    if not isinstance(value, str) or not value.strip():
        raise TargetMatrixError(f"target matrix {field} must be a non-empty string")
    return value.strip()


def _non_negative_int(value: object, field: str) -> int:
    """Validate and return non-negative integer from target matrix."""
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise TargetMatrixError(
            f"target matrix {field} must be a non-negative integer, got {value!r}"
        )
    return value


def _positive_int(value: object, field: str) -> int:
    """Validate and return strictly positive integer from target matrix."""
    value = _non_negative_int(value, field)
    if value == 0:
        raise TargetMatrixError(f"target matrix {field} must be positive")
    return value


def _string_array(value: object, field: str) -> tuple[str, ...]:
    """Validate and return unique tuple of non-empty strings from target matrix."""
    if not isinstance(value, list) or not value:
        raise TargetMatrixError(f"target matrix {field} must be a non-empty string array")
    rows = tuple(_text(item, f"{field}[{index}]") for index, item in enumerate(value))
    if len(set(rows)) != len(rows):
        raise TargetMatrixError(f"target matrix {field} contains duplicates")
    return rows


def load_target_matrix(path: str | pathlib.Path) -> TargetMatrix:
    """Load and strictly validate the complete target identity matrix."""
    matrix_path = pathlib.Path(path)
    try:
        payload = tomllib.loads(matrix_path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise TargetMatrixError(f"cannot load target matrix {matrix_path}: {exc}") from exc
    if not isinstance(payload, dict) or set(payload) != {
        "schema_version", "software", "target"
    }:
        raise TargetMatrixError(
            "target matrix fields must be exactly schema_version, software, and target"
        )
    if payload["schema_version"] != TARGET_SCHEMA_VERSION:
        raise TargetMatrixError(
            f"target matrix schema_version must be {TARGET_SCHEMA_VERSION}"
        )
    raw_software = payload["software"]
    software_fields = {
        "workspace_version",
        "rustc",
        "python",
        "vyre",
        "hyperscan",
        "workload_catalog",
        "fixture_lock",
    }
    if not isinstance(raw_software, dict) or set(raw_software) != software_fields:
        raise TargetMatrixError(
            f"target matrix software fields must be exactly {sorted(software_fields)}"
        )
    software = SoftwareIdentity(
        workspace_version=_text(raw_software["workspace_version"], "software.workspace_version"),
        rustc=_text(raw_software["rustc"], "software.rustc"),
        python=_text(raw_software["python"], "software.python"),
        vyre=_text(raw_software["vyre"], "software.vyre"),
        hyperscan=_text(raw_software["hyperscan"], "software.hyperscan"),
        workload_catalog=_text(
            raw_software["workload_catalog"], "software.workload_catalog"
        ),
        fixture_lock=_text(raw_software["fixture_lock"], "software.fixture_lock"),
    )

    raw_targets = payload["target"]
    if not isinstance(raw_targets, list) or not raw_targets:
        raise TargetMatrixError("target matrix requires at least one [[target]]")
    target_fields = {
        "id",
        "os",
        "arch",
        "class",
        "identity_mode",
        "cpu",
        "logical_cores",
        "min_ram_mb",
        "gpu",
        "min_gpu_vram_mb",
        "gpu_driver",
        "required_backends",
        "evidence",
    }
    targets: list[TargetIdentity] = []
    seen: set[str] = set()
    for index, raw in enumerate(raw_targets):
        if not isinstance(raw, dict) or set(raw) != target_fields:
            raise TargetMatrixError(
                f"target[{index}] fields must be exactly {sorted(target_fields)}"
            )
        target_id = _text(raw["id"], f"target[{index}].id")
        if target_id in seen:
            raise TargetMatrixError(f"target matrix duplicates target {target_id!r}")
        seen.add(target_id)
        os_name = _text(raw["os"], f"target[{index}].os")
        arch = _text(raw["arch"], f"target[{index}].arch")
        identity_mode = _text(
            raw["identity_mode"], f"target[{index}].identity_mode"
        )
        if os_name not in ALLOWED_OSES:
            raise TargetMatrixError(f"target {target_id!r} has unsupported OS {os_name!r}")
        if arch not in ALLOWED_ARCHES:
            raise TargetMatrixError(f"target {target_id!r} has unsupported arch {arch!r}")
        if identity_mode not in ALLOWED_IDENTITY_MODES:
            raise TargetMatrixError(
                f"target {target_id!r} has unsupported identity_mode {identity_mode!r}"
            )
        required_backends = _string_array(
            raw["required_backends"], f"target[{index}].required_backends"
        )
        unsupported = set(required_backends) - ALLOWED_BACKENDS
        if unsupported:
            raise TargetMatrixError(
                f"target {target_id!r} has unsupported backends {sorted(unsupported)}"
            )
        if "cpu" not in required_backends or "auto" not in required_backends:
            raise TargetMatrixError(
                f"target {target_id!r} must gate both cpu and auto backends"
            )
        targets.append(
            TargetIdentity(
                target_id=target_id,
                os=os_name,
                arch=arch,
                target_class=_text(raw["class"], f"target[{index}].class"),
                identity_mode=identity_mode,
                cpu=_text(raw["cpu"], f"target[{index}].cpu"),
                logical_cores=_positive_int(
                    raw["logical_cores"], f"target[{index}].logical_cores"
                ),
                min_ram_mb=_positive_int(
                    raw["min_ram_mb"], f"target[{index}].min_ram_mb"
                ),
                gpu=_text(raw["gpu"], f"target[{index}].gpu"),
                min_gpu_vram_mb=_non_negative_int(
                    raw["min_gpu_vram_mb"], f"target[{index}].min_gpu_vram_mb"
                ),
                gpu_driver=_text(
                    raw["gpu_driver"], f"target[{index}].gpu_driver"
                ),
                required_backends=required_backends,
                evidence=_text(raw["evidence"], f"target[{index}].evidence"),
            )
        )
    if seen != REQUIRED_TARGET_IDS:
        raise TargetMatrixError(
            "target matrix does not cover the required release hosts; "
            f"missing={sorted(REQUIRED_TARGET_IDS - seen)}, "
            f"extra={sorted(seen - REQUIRED_TARGET_IDS)}"
        )
    return TargetMatrix(
        schema_version=TARGET_SCHEMA_VERSION,
        software=software,
        targets=tuple(targets),
    )


def validate_target_evidence(matrix: TargetMatrix, benchmarks_root: str | pathlib.Path) -> None:
    """Require every pinned target to reference existing immutable evidence bytes."""
    root = pathlib.Path(benchmarks_root).resolve()
    missing: list[str] = []
    for target in matrix.targets:
        relative = pathlib.PurePosixPath(target.evidence)
        if relative.is_absolute() or ".." in relative.parts:
            raise TargetMatrixError(
                f"target {target.target_id!r} evidence must be benchmark-relative"
            )
        evidence = root / pathlib.Path(*relative.parts)
        if not evidence.is_file():
            missing.append(f"{target.target_id}={target.evidence}")
    catalog = root / matrix.software.workload_catalog
    fixture_lock = root / matrix.software.fixture_lock
    for label, path in (("workload_catalog", catalog), ("fixture_lock", fixture_lock)):
        if not path.is_file():
            missing.append(f"software.{label}={path.name}")
    if missing:
        raise TargetMatrixError("target matrix evidence does not exist: " + ", ".join(missing))


def target_matrix_sha256(path: str | pathlib.Path) -> str:
    """Return the exact target matrix identity included in benchmark receipts."""
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()
