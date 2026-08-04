"""Nightly cross-platform, cross-device profiling matrix.

The matrix configuration (``benchmarks/profile-matrix/nightly.toml``)
declares the devices and workloads the nightly profiling run covers; this
module validates that declaration and expands it into a deterministic job
plan. CI wiring consumes the plan; this module owns only the config contract
and the expansion.
"""

from __future__ import annotations

import pathlib
import tomllib
from dataclasses import dataclass

MATRIX_SCHEMA_VERSION = 1


class MatrixError(ValueError):
    """A profiling matrix configuration that is malformed or undecidable."""


@dataclass(frozen=True)
class MatrixDevice:
    """One device lane the nightly matrix profiles on."""

    device_id: str
    os: str
    arch: str
    device_class: str


@dataclass(frozen=True)
class MatrixWorkload:
    """One workload profiled on every device lane."""

    name: str
    corpus: str
    config_id: str
    budgets: str
    cold: int
    warm: int
    steady: int
    seed: int


@dataclass(frozen=True)
class ProfileMatrix:
    """The validated nightly matrix declaration."""

    schema_version: int
    cadence: str
    devices: tuple[MatrixDevice, ...]
    workloads: tuple[MatrixWorkload, ...]


def _non_empty_str(value: object, field_name: str) -> str:
    if not isinstance(value, str) or not value:
        raise MatrixError(f"matrix {field_name} must be a non-empty string")
    return value


def _non_negative_int(value: object, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise MatrixError(
            f"matrix {field_name} must be a non-negative integer, got {value!r}"
        )
    return value


def load_matrix(path: str | pathlib.Path) -> ProfileMatrix:
    """Load and strictly validate one matrix TOML file."""
    matrix_path = pathlib.Path(path)
    try:
        data = tomllib.loads(matrix_path.read_text())
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise MatrixError(f"cannot load matrix file {matrix_path}: {exc}") from exc
    if not isinstance(data, dict):
        raise MatrixError(f"matrix file {matrix_path} must be a TOML table")
    schema_version = data.get("schema_version")
    if schema_version != MATRIX_SCHEMA_VERSION:
        raise MatrixError(
            f"matrix file {matrix_path} schema_version must be "
            f"{MATRIX_SCHEMA_VERSION}, got {schema_version!r}"
        )
    cadence = _non_empty_str(data.get("cadence"), "cadence")
    raw_devices = data.get("device")
    if not isinstance(raw_devices, list) or not raw_devices:
        raise MatrixError(
            f"matrix file {matrix_path} must declare at least one [[device]]"
        )
    devices: list[MatrixDevice] = []
    seen_devices: set[str] = set()
    for index, raw in enumerate(raw_devices):
        if not isinstance(raw, dict):
            raise MatrixError(f"matrix device[{index}] must be a TOML table")
        unknown = set(raw) - {"id", "os", "arch", "class"}
        if unknown:
            raise MatrixError(
                f"matrix device[{index}] has unknown fields: {sorted(unknown)}"
            )
        device_id = _non_empty_str(raw.get("id"), f"device[{index}].id")
        if device_id in seen_devices:
            raise MatrixError(f"matrix declares duplicate device {device_id!r}")
        seen_devices.add(device_id)
        devices.append(
            MatrixDevice(
                device_id=device_id,
                os=_non_empty_str(raw.get("os"), f"device[{index}].os"),
                arch=_non_empty_str(raw.get("arch"), f"device[{index}].arch"),
                device_class=_non_empty_str(
                    raw.get("class"), f"device[{index}].class"
                ),
            )
        )
    raw_workloads = data.get("workload")
    if not isinstance(raw_workloads, list) or not raw_workloads:
        raise MatrixError(
            f"matrix file {matrix_path} must declare at least one [[workload]]"
        )
    workloads: list[MatrixWorkload] = []
    seen_workloads: set[str] = set()
    for index, raw in enumerate(raw_workloads):
        if not isinstance(raw, dict):
            raise MatrixError(f"matrix workload[{index}] must be a TOML table")
        unknown = set(raw) - {
            "name", "corpus", "config_id", "budgets",
            "cold", "warm", "steady", "seed",
        }
        if unknown:
            raise MatrixError(
                f"matrix workload[{index}] has unknown fields: {sorted(unknown)}"
            )
        name = _non_empty_str(raw.get("name"), f"workload[{index}].name")
        if name in seen_workloads:
            raise MatrixError(f"matrix declares duplicate workload {name!r}")
        seen_workloads.add(name)
        cold = _non_negative_int(raw.get("cold"), f"workload[{index}].cold")
        warm = _non_negative_int(raw.get("warm"), f"workload[{index}].warm")
        steady = _non_negative_int(raw.get("steady"), f"workload[{index}].steady")
        if cold + warm + steady == 0:
            raise MatrixError(
                f"matrix workload {name!r} must run at least one trial"
            )
        workloads.append(
            MatrixWorkload(
                name=name,
                corpus=_non_empty_str(
                    raw.get("corpus"), f"workload[{index}].corpus"
                ),
                config_id=_non_empty_str(
                    raw.get("config_id"), f"workload[{index}].config_id"
                ),
                budgets=_non_empty_str(
                    raw.get("budgets"), f"workload[{index}].budgets"
                ),
                cold=cold,
                warm=warm,
                steady=steady,
                seed=_non_negative_int(raw.get("seed"), f"workload[{index}].seed"),
            )
        )
    return ProfileMatrix(
        schema_version=schema_version,
        cadence=cadence,
        devices=tuple(devices),
        workloads=tuple(workloads),
    )


@dataclass(frozen=True)
class MatrixJob:
    """One (device, workload) profiling job in deterministic plan order."""

    job_id: str
    device: MatrixDevice
    workload: MatrixWorkload

    def to_json(self) -> dict:
        return {
            "job_id": self.job_id,
            "device": {
                "id": self.device.device_id,
                "os": self.device.os,
                "arch": self.device.arch,
                "class": self.device.device_class,
            },
            "workload": {
                "name": self.workload.name,
                "corpus": self.workload.corpus,
                "config_id": self.workload.config_id,
                "budgets": self.workload.budgets,
                "cold": self.workload.cold,
                "warm": self.workload.warm,
                "steady": self.workload.steady,
                "seed": self.workload.seed,
            },
        }


def plan_jobs(matrix: ProfileMatrix) -> tuple[MatrixJob, ...]:
    """Expand the matrix into the deterministic device-major job order."""
    jobs = [
        MatrixJob(
            job_id=f"{device.device_id}/{workload.name}",
            device=device,
            workload=workload,
        )
        for device in matrix.devices
        for workload in matrix.workloads
    ]
    return tuple(sorted(jobs, key=lambda job: job.job_id))
