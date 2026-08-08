"""Canonical performance workload and hard-target contract.

The catalog is the one inventory consumed by benchmark planning. It separates
operator workloads from measurement dimensions so every workload can be crossed
with every applicable policy, backend, cache state, output, and execution route
without duplicating hand-maintained lists.
"""

from __future__ import annotations

import pathlib
import re
import tomllib
from dataclasses import dataclass

CATALOG_SCHEMA_VERSION = 1
CPU_SIMD_MAX_RSS_BYTES = 128 * 1024 * 1024
MIN_SPEEDUP = 2.0
MAX_RSS_RATIO = 0.25
MAX_VRAM_RATIO = 0.25
MAX_BETTERLEAKS_TIME_RATIO = 0.25
MIN_GPU_SPEEDUP = 10.0

REQUIRED_POLICIES = frozenset({"default", "fast", "deep", "precision"})
REQUIRED_BACKENDS = frozenset(
    {"auto", "cpu", "simd", "gpu-cuda", "gpu-wgpu", "gpu-metal"}
)
REQUIRED_CACHE_STATES = frozenset(
    {"cold", "warm", "steady", "incremental-warm"}
)
REQUIRED_OUTPUTS = frozenset(
    {"text", "json", "json-envelope", "jsonl", "sarif"}
)
REQUIRED_EXECUTION_ROUTES = frozenset(
    {"in-process", "warm-daemon", "mass-daemon"}
)
REQUIRED_FAMILIES = frozenset(
    {
        "filesystem",
        "stdin",
        "git",
        "github",
        "gitlab",
        "bitbucket",
        "cloud",
        "container",
        "web",
        "slack",
        "daemon",
        "incremental",
        "watch",
        "system",
        "verification",
        "concurrency",
    }
)
_ID_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")


class WorkloadCatalogError(ValueError):
    """A workload declaration that cannot prove the performance contract."""


@dataclass(frozen=True)
class Workload:
    """One independently gated operator workload class."""

    workload_id: str
    family: str
    surface: str
    owner: str
    fixture: str
    execution_routes: tuple[str, ...]
    betterleaks_comparable: bool
    gpu_eligible: bool


@dataclass(frozen=True)
class PerformanceTargets:
    """Release-blocking performance and memory floors."""

    min_speedup: float
    max_rss_ratio: float
    max_vram_ratio: float
    cpu_simd_max_rss_bytes: int
    betterleaks_max_time_ratio: float
    gpu_min_speedup: float


@dataclass(frozen=True)
class WorkloadDimensions:
    """Axes crossed with each workload when the route supports them."""

    policies: tuple[str, ...]
    backends: tuple[str, ...]
    cache_states: tuple[str, ...]
    outputs: tuple[str, ...]
    execution_routes: tuple[str, ...]


@dataclass(frozen=True)
class WorkloadCatalog:
    """Validated complete inventory and its release targets."""

    schema_version: int
    targets: PerformanceTargets
    dimensions: WorkloadDimensions
    workloads: tuple[Workload, ...]


def _number(value: object, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise WorkloadCatalogError(f"catalog {field} must be a number, got {value!r}")
    return float(value)


def _positive_int(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise WorkloadCatalogError(
            f"catalog {field} must be a positive integer, got {value!r}"
        )
    return value


def _text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise WorkloadCatalogError(f"catalog {field} must be a non-empty string")
    return value.strip()


def _bool(value: object, field: str) -> bool:
    if not isinstance(value, bool):
        raise WorkloadCatalogError(f"catalog {field} must be a boolean, got {value!r}")
    return value


def _text_array(value: object, field: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not value:
        raise WorkloadCatalogError(f"catalog {field} must be a non-empty string array")
    rows = tuple(_text(item, f"{field}[{index}]") for index, item in enumerate(value))
    if len(set(rows)) != len(rows):
        raise WorkloadCatalogError(f"catalog {field} contains duplicate values")
    return rows


def _exact_axis(value: object, field: str, required: frozenset[str]) -> tuple[str, ...]:
    rows = _text_array(value, field)
    observed = frozenset(rows)
    if observed != required:
        missing = sorted(required - observed)
        extra = sorted(observed - required)
        raise WorkloadCatalogError(
            f"catalog {field} does not match the required axis; "
            f"missing={missing}, extra={extra}"
        )
    return rows


def load_workload_catalog(path: str | pathlib.Path) -> WorkloadCatalog:
    """Load one strict workload catalog and reject weakened coverage or targets."""
    catalog_path = pathlib.Path(path)
    try:
        payload = tomllib.loads(catalog_path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise WorkloadCatalogError(f"cannot load workload catalog {catalog_path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise WorkloadCatalogError("workload catalog must be a TOML table")
    allowed_top = {"schema_version", "targets", "dimensions", "workload"}
    unknown_top = set(payload) - allowed_top
    if unknown_top:
        raise WorkloadCatalogError(
            f"workload catalog has unknown top-level fields: {sorted(unknown_top)}"
        )
    if payload.get("schema_version") != CATALOG_SCHEMA_VERSION:
        raise WorkloadCatalogError(
            f"workload catalog schema_version must be {CATALOG_SCHEMA_VERSION}, "
            f"got {payload.get('schema_version')!r}"
        )

    raw_targets = payload.get("targets")
    if not isinstance(raw_targets, dict):
        raise WorkloadCatalogError("workload catalog requires a [targets] table")
    target_fields = {
        "min_speedup",
        "max_rss_ratio",
        "max_vram_ratio",
        "cpu_simd_max_rss_bytes",
        "betterleaks_max_time_ratio",
        "gpu_min_speedup",
    }
    if set(raw_targets) != target_fields:
        raise WorkloadCatalogError(
            "catalog targets fields must be exactly " f"{sorted(target_fields)}"
        )
    targets = PerformanceTargets(
        min_speedup=_number(raw_targets["min_speedup"], "targets.min_speedup"),
        max_rss_ratio=_number(raw_targets["max_rss_ratio"], "targets.max_rss_ratio"),
        max_vram_ratio=_number(raw_targets["max_vram_ratio"], "targets.max_vram_ratio"),
        cpu_simd_max_rss_bytes=_positive_int(
            raw_targets["cpu_simd_max_rss_bytes"],
            "targets.cpu_simd_max_rss_bytes",
        ),
        betterleaks_max_time_ratio=_number(
            raw_targets["betterleaks_max_time_ratio"],
            "targets.betterleaks_max_time_ratio",
        ),
        gpu_min_speedup=_number(
            raw_targets["gpu_min_speedup"], "targets.gpu_min_speedup"
        ),
    )
    if targets.min_speedup < MIN_SPEEDUP:
        raise WorkloadCatalogError(f"min_speedup cannot be below {MIN_SPEEDUP}")
    if not 0.0 < targets.max_rss_ratio <= MAX_RSS_RATIO:
        raise WorkloadCatalogError(f"max_rss_ratio cannot exceed {MAX_RSS_RATIO}")
    if not 0.0 < targets.max_vram_ratio <= MAX_VRAM_RATIO:
        raise WorkloadCatalogError(f"max_vram_ratio cannot exceed {MAX_VRAM_RATIO}")
    if targets.cpu_simd_max_rss_bytes > CPU_SIMD_MAX_RSS_BYTES:
        raise WorkloadCatalogError(
            f"cpu_simd_max_rss_bytes cannot exceed {CPU_SIMD_MAX_RSS_BYTES}"
        )
    if not 0.0 < targets.betterleaks_max_time_ratio <= MAX_BETTERLEAKS_TIME_RATIO:
        raise WorkloadCatalogError(
            "betterleaks_max_time_ratio cannot exceed "
            f"{MAX_BETTERLEAKS_TIME_RATIO}"
        )
    if targets.gpu_min_speedup < MIN_GPU_SPEEDUP:
        raise WorkloadCatalogError(
            f"gpu_min_speedup cannot be below {MIN_GPU_SPEEDUP}"
        )

    raw_dimensions = payload.get("dimensions")
    if not isinstance(raw_dimensions, dict):
        raise WorkloadCatalogError("workload catalog requires a [dimensions] table")
    dimension_fields = {
        "policies",
        "backends",
        "cache_states",
        "outputs",
        "execution_routes",
    }
    if set(raw_dimensions) != dimension_fields:
        raise WorkloadCatalogError(
            "catalog dimensions fields must be exactly " f"{sorted(dimension_fields)}"
        )
    dimensions = WorkloadDimensions(
        policies=_exact_axis(
            raw_dimensions["policies"], "dimensions.policies", REQUIRED_POLICIES
        ),
        backends=_exact_axis(
            raw_dimensions["backends"], "dimensions.backends", REQUIRED_BACKENDS
        ),
        cache_states=_exact_axis(
            raw_dimensions["cache_states"],
            "dimensions.cache_states",
            REQUIRED_CACHE_STATES,
        ),
        outputs=_exact_axis(
            raw_dimensions["outputs"], "dimensions.outputs", REQUIRED_OUTPUTS
        ),
        execution_routes=_exact_axis(
            raw_dimensions["execution_routes"],
            "dimensions.execution_routes",
            REQUIRED_EXECUTION_ROUTES,
        ),
    )

    raw_workloads = payload.get("workload")
    if not isinstance(raw_workloads, list) or not raw_workloads:
        raise WorkloadCatalogError("workload catalog requires at least one [[workload]]")
    workload_fields = {
        "id",
        "family",
        "surface",
        "owner",
        "fixture",
        "execution_routes",
        "betterleaks_comparable",
        "gpu_eligible",
    }
    workloads: list[Workload] = []
    seen_ids: set[str] = set()
    for index, raw in enumerate(raw_workloads):
        if not isinstance(raw, dict) or set(raw) != workload_fields:
            observed = sorted(raw) if isinstance(raw, dict) else type(raw).__name__
            raise WorkloadCatalogError(
                f"catalog workload[{index}] fields must be exactly "
                f"{sorted(workload_fields)}, got {observed}"
            )
        workload_id = _text(raw["id"], f"workload[{index}].id")
        if not _ID_RE.fullmatch(workload_id):
            raise WorkloadCatalogError(
                f"catalog workload id {workload_id!r} must be lowercase kebab-case"
            )
        if workload_id in seen_ids:
            raise WorkloadCatalogError(
                f"workload catalog declares duplicate id {workload_id!r}"
            )
        seen_ids.add(workload_id)
        family = _text(raw["family"], f"workload[{index}].family")
        if family not in REQUIRED_FAMILIES:
            raise WorkloadCatalogError(
                f"catalog workload {workload_id!r} has unknown family {family!r}"
            )
        routes = _text_array(
            raw["execution_routes"], f"workload[{index}].execution_routes"
        )
        unsupported_routes = set(routes) - REQUIRED_EXECUTION_ROUTES
        if unsupported_routes:
            raise WorkloadCatalogError(
                f"catalog workload {workload_id!r} has unsupported execution routes "
                f"{sorted(unsupported_routes)}"
            )
        workloads.append(
            Workload(
                workload_id=workload_id,
                family=family,
                surface=_text(raw["surface"], f"workload[{index}].surface"),
                owner=_text(raw["owner"], f"workload[{index}].owner"),
                fixture=_text(raw["fixture"], f"workload[{index}].fixture"),
                execution_routes=routes,
                betterleaks_comparable=_bool(
                    raw["betterleaks_comparable"],
                    f"workload[{index}].betterleaks_comparable",
                ),
                gpu_eligible=_bool(
                    raw["gpu_eligible"], f"workload[{index}].gpu_eligible"
                ),
            )
        )
    observed_families = {workload.family for workload in workloads}
    missing_families = sorted(REQUIRED_FAMILIES - observed_families)
    if missing_families:
        raise WorkloadCatalogError(
            f"workload catalog omits required families: {missing_families}"
        )
    if not any(workload.betterleaks_comparable for workload in workloads):
        raise WorkloadCatalogError("workload catalog has no Betterleaks comparison workloads")
    if not any(workload.gpu_eligible for workload in workloads):
        raise WorkloadCatalogError("workload catalog has no GPU-eligible workloads")

    return WorkloadCatalog(
        schema_version=CATALOG_SCHEMA_VERSION,
        targets=targets,
        dimensions=dimensions,
        workloads=tuple(workloads),
    )


def validate_owner_paths(
    catalog: WorkloadCatalog, repo_root: str | pathlib.Path
) -> None:
    """Require every workload to name an existing repository-owned implementation or fixture."""
    root = pathlib.Path(repo_root).resolve()
    missing: list[str] = []
    invalid: list[str] = []
    for workload in catalog.workloads:
        for kind, declared in (("owner", workload.owner), ("fixture", workload.fixture)):
            raw_path = declared.partition(":")[0]
            relative = pathlib.PurePosixPath(raw_path)
            label = f"{workload.workload_id}.{kind}={declared}"
            if relative.is_absolute() or ".." in relative.parts:
                invalid.append(label)
                continue
            if not (root / pathlib.Path(*relative.parts)).exists():
                missing.append(label)
    if invalid:
        raise WorkloadCatalogError(
            "workload catalog owner paths must be repository-relative: "
            + ", ".join(invalid)
        )
    if missing:
        raise WorkloadCatalogError(
            "workload catalog owner paths do not exist: " + ", ".join(missing)
        )
