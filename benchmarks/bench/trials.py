"""Cache-state-controlled benchmark trials with host-noise receipts.

One :class:`TrialSet` is a repeatable measurement unit: cold trials clear the
keyhog caches before each run, warm trials run after one untimed priming run,
and steady trials run back to back with the cache state the warm phase left.
Every trial carries a :class:`NoiseReceipt` recording the host-noise controls
(affinity, CPU governor/frequency, load average) in force around the run; a
trial whose controls were not applied is marked invalid with an explicit
reason and excluded from gate statistics, never silently dropped.
"""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
from dataclasses import dataclass
from enum import Enum
from typing import Callable

from .schema import ProfileArtifact

TRIAL_SET_SCHEMA_VERSION = "trial-set-v1"
GOVERNOR_UNKNOWN = "unknown"


class CacheState(str, Enum):
    """The cache condition a trial is measured under."""

    COLD = "cold"
    WARM = "warm"
    STEADY = "steady"
    INCREMENTAL_WARM = "incremental-warm"


class ExecutionRoute(str, Enum):
    """The process execution route a trial is measured under."""

    IN_PROCESS = "in-process"
    WARM_DAEMON = "warm-daemon"
    MASS_DAEMON = "mass-daemon"

@dataclass(frozen=True)
class NoiseReceipt:
    """The host-noise controls observed around one trial."""

    affinity_requested: bool
    affinity_applied: bool
    affinity_cpus: int
    governor: str
    governor_required: str
    frequency_mhz: float
    load_avg_before: tuple[float, float, float]
    load_avg_after: tuple[float, float, float]

    def violations(self) -> list[str]:
        """Noise controls that were required but not applied (empty == clean)."""
        out: list[str] = []
        if self.affinity_requested and not self.affinity_applied:
            out.append("affinity pinning was requested but not applied")
        if (
            self.governor_required
            and self.governor != self.governor_required
        ):
            out.append(
                f"CPU governor is {self.governor!r}, required "
                f"{self.governor_required!r}"
            )
        return out

    def to_json(self) -> dict:
        """Serialize NoiseReceipt to JSON dictionary."""
        return {
            "affinity_requested": self.affinity_requested,
            "affinity_applied": self.affinity_applied,
            "affinity_cpus": self.affinity_cpus,
            "governor": self.governor,
            "governor_required": self.governor_required,
            "frequency_mhz": self.frequency_mhz,
            "load_avg_before": list(self.load_avg_before),
            "load_avg_after": list(self.load_avg_after),
        }

    @classmethod
    def from_json(cls, value: object) -> "NoiseReceipt":
        """Deserialize NoiseReceipt from JSON dictionary."""
        if not isinstance(value, dict):
            raise ValueError("noise receipt must be an object")
        required = set(cls.__dataclass_fields__)
        missing = sorted(required - set(value))
        extra = sorted(set(value) - required)
        if missing:
            raise ValueError(f"noise receipt missing required fields: {missing}")
        if extra:
            raise ValueError(f"noise receipt has unknown fields: {extra}")
        load_before = value["load_avg_before"]
        load_after = value["load_avg_after"]
        if not isinstance(load_before, list) or len(load_before) != 3:
            raise ValueError("noise receipt load_avg_before must be three floats")
        if not isinstance(load_after, list) or len(load_after) != 3:
            raise ValueError("noise receipt load_avg_after must be three floats")
        return cls(
            affinity_requested=bool(value["affinity_requested"]),
            affinity_applied=bool(value["affinity_applied"]),
            affinity_cpus=int(value["affinity_cpus"]),
            governor=str(value["governor"]),
            governor_required=str(value["governor_required"]),
            frequency_mhz=float(value["frequency_mhz"]),
            load_avg_before=tuple(float(v) for v in load_before),
            load_avg_after=tuple(float(v) for v in load_after),
        )


@dataclass(frozen=True)
class Trial:
    """One measured repetition with its cache state and noise receipt."""

    index: int
    cache_state: str
    wall_ms: float
    profile: ProfileArtifact | None
    noise: NoiseReceipt
    invalid_reasons: tuple[str, ...]

    @property
    def valid(self) -> bool:
        """Return True if trial was not invalidated by noise or control failures."""
        return not self.invalid_reasons

    def to_json(self) -> dict:
        """Serialize Trial to JSON dictionary."""
        return {
            "index": self.index,
            "cache_state": self.cache_state,
            "wall_ms": self.wall_ms,
            "profile": self.profile.to_json() if self.profile is not None else None,
            "noise": self.noise.to_json(),
            "invalid_reasons": list(self.invalid_reasons),
        }

    @classmethod
    def from_json(cls, value: object) -> "Trial":
        """Deserialize Trial from JSON dictionary."""
        if not isinstance(value, dict):
            raise ValueError("trial must be an object")
        raw_profile = value.get("profile")
        return cls(
            index=int(value["index"]),
            cache_state=str(value["cache_state"]),
            wall_ms=float(value["wall_ms"]),
            profile=(
                ProfileArtifact.from_json(raw_profile)
                if raw_profile is not None
                else None
            ),
            noise=NoiseReceipt.from_json(value["noise"]),
            invalid_reasons=tuple(str(v) for v in value["invalid_reasons"]),
        )


@dataclass(frozen=True)
class TrialSet:
    """One workload's full cold/warm/steady repetition set."""

    schema_version: str
    workload: str
    role: str
    trials: tuple[Trial, ...]

    def __post_init__(self) -> None:
        """Validate TrialSet schema version and role invariants."""
        if self.schema_version != TRIAL_SET_SCHEMA_VERSION:
            raise ValueError(
                f"trial set schema_version must be {TRIAL_SET_SCHEMA_VERSION!r}, "
                f"got {self.schema_version!r}"
            )
        if self.role not in ("control", "candidate", "unprofiled"):
            raise ValueError(f"trial set role is invalid: {self.role!r}")

    def valid_wall_ms(self, cache_state: CacheState | None = None) -> list[float]:
        """Wall times of valid trials, optionally one cache state only."""
        return [
            trial.wall_ms
            for trial in self.trials
            if trial.valid
            and (cache_state is None or trial.cache_state == cache_state.value)
        ]

    def canonical_json(self) -> str:
        """Return deterministic compact JSON representation for hashing."""
        return json.dumps(self.to_json(), sort_keys=True, separators=(",", ":"))

    def digest(self) -> str:
        """Content digest binding receipts and gates to this exact trial set."""
        return hashlib.sha256(self.canonical_json().encode("utf-8")).hexdigest()

    def to_json(self) -> dict:
        """Serialize TrialSet to JSON dictionary."""
        return {
            "schema_version": self.schema_version,
            "workload": self.workload,
            "role": self.role,
            "trials": [trial.to_json() for trial in self.trials],
        }

    @classmethod
    def from_json(cls, value: object) -> "TrialSet":
        """Deserialize TrialSet from JSON dictionary."""
        if not isinstance(value, dict):
            raise ValueError("trial set must be an object")
        return cls(
            schema_version=str(value["schema_version"]),
            workload=str(value["workload"]),
            role=str(value["role"]),
            trials=tuple(Trial.from_json(t) for t in value["trials"]),
        )


@dataclass(frozen=True)
class TrialOutcome:
    """What one executor invocation measured."""

    wall_ms: float
    profile: ProfileArtifact | None = None


# (state, trial index within the run) -> measurement. Priming uses index -1.
TrialExecutor = Callable[[CacheState, int], TrialOutcome]


@dataclass(frozen=True)
class NoiseProber:
    """Host probes, injectable so tests never touch real sysfs or load."""

    affinity: Callable[[], tuple[bool, int]]
    governor: Callable[[], tuple[str, float]]
    load: Callable[[], tuple[float, float, float]]


def _probe_affinity() -> tuple[bool, int]:
    """Probe current process CPU affinity settings."""
    try:
        cpus = os.sched_getaffinity(0)
    except (AttributeError, OSError):
        return (False, 0)
    return (True, len(cpus))


def _probe_governor(
    cpufreq: pathlib.Path = pathlib.Path("/sys/devices/system/cpu/cpu0/cpufreq"),
) -> tuple[str, float]:
    """Probe current CPU scaling governor and operating frequency."""
    try:
        governor = (cpufreq / "scaling_governor").read_text().strip()
    except OSError:
        governor = GOVERNOR_UNKNOWN
    try:
        frequency_mhz = int((cpufreq / "scaling_cur_freq").read_text().strip()) / 1000.0
    except (OSError, ValueError):
        frequency_mhz = 0.0
    return (governor, frequency_mhz)


def default_noise_prober() -> NoiseProber:
    """Probes against the real host (Linux cpufreq; unknown elsewhere)."""
    return NoiseProber(
        affinity=_probe_affinity,
        governor=_probe_governor,
        load=os.getloadavg,
    )


def apply_affinity() -> tuple[bool, int]:
    """Pin this process to its current allowed set, explicitly and audibly.

    Restricting to the already-allowed set needs no privilege and makes the
    affinity control applied rather than assumed; child executors inherit it.
    """
    try:
        cpus = os.sched_getaffinity(0)
        if not cpus:
            return (False, 0)
        os.sched_setaffinity(0, cpus)
        return (True, len(cpus))
    except (AttributeError, OSError):
        return (False, 0)


def run_trials(
    *,
    workload: str,
    role: str,
    executor: TrialExecutor,
    cold: int = 1,
    warm: int = 1,
    steady: int = 3,
    pin_affinity: bool = True,
    governor_required: str = "",
    clear_caches: Callable[[], None] | None = None,
    prober: NoiseProber | None = None,
) -> TrialSet:
    """Run the cold/warm/steady repetition plan and receipt every trial.

    A cold trial without a ``clear_caches`` hook is invalid (its cache state
    is unproven); warm trials are preceded by exactly one untimed priming
    executor call; steady trials run back to back. Trials whose noise
    controls were not applied carry explicit ``invalid_reasons``.
    """
    if min(cold, warm, steady) < 0:
        raise ValueError("trial counts must be non-negative")
    if cold + warm + steady == 0:
        raise ValueError("at least one trial is required")
    if prober is None:
        prober = default_noise_prober()
    affinity_applied, affinity_cpus = (
        apply_affinity() if pin_affinity else (False, 0)
    )

    trials: list[Trial] = []
    index = 0

    def record(state: CacheState) -> None:
        """Execute trial under state and record noise and measurement results."""
        nonlocal index
        invalid: list[str] = []
        if pin_affinity and not affinity_applied:
            invalid.append("affinity pinning was requested but not applied")
        if state is CacheState.COLD and clear_caches is None:
            invalid.append("cold trial ran without a cache-clear hook")
        load_before = prober.load()
        governor, frequency_mhz = prober.governor()
        outcome = executor(state, index)
        load_after = prober.load()
        noise = NoiseReceipt(
            affinity_requested=pin_affinity,
            affinity_applied=affinity_applied,
            affinity_cpus=affinity_cpus,
            governor=governor,
            governor_required=governor_required,
            frequency_mhz=frequency_mhz,
            load_avg_before=load_before,
            load_avg_after=load_after,
        )
        invalid.extend(noise.violations())
        if outcome.wall_ms <= 0.0:
            invalid.append(
                f"executor reported a non-positive wall time {outcome.wall_ms!r}"
            )
        trials.append(
            Trial(
                index=index,
                cache_state=state.value,
                wall_ms=outcome.wall_ms,
                profile=outcome.profile,
                noise=noise,
                invalid_reasons=tuple(dict.fromkeys(invalid)),
            )
        )
        index += 1

    for _ in range(cold):
        if clear_caches is not None:
            clear_caches()
        record(CacheState.COLD)
    if warm > 0:
        executor(CacheState.WARM, -1)  # untimed priming run
        for _ in range(warm):
            record(CacheState.WARM)
    for _ in range(steady):
        record(CacheState.STEADY)

    return TrialSet(
        schema_version=TRIAL_SET_SCHEMA_VERSION,
        workload=workload,
        role=role,
        trials=tuple(trials),
    )
