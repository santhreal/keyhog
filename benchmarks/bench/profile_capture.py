"""Paired control/candidate profile capture.

Runs both binaries of a benchmark pair over the same workload with causal
profile capture enabled (``--profile-out <PATH>``) and stores both artifacts
alongside the run results. Finding-bearing and coverage-gap scan exits are
successful; an execution failure or a missing/invalid artifact is a hard error.
"""

from __future__ import annotations

import pathlib
import shlex
import subprocess
import time
from dataclasses import dataclass
from typing import Callable, Sequence

from .profile_artifact import PROFILE_OUT_FLAG, artifact_for
from .schema import ProfileArtifact
from .trials import TrialOutcome


SUCCESSFUL_SCAN_EXITS = frozenset({0, 1, 10, 13})


class ProfileCaptureError(RuntimeError):
    """A profiled run that failed or left no valid artifact."""


@dataclass(frozen=True)
class CaptureOutcome:
    """One raw profiled subprocess execution."""

    exit_code: int
    wall_ms: float


# argv (already carrying --profile-out) -> raw execution result.
CaptureRunner = Callable[[Sequence[str]], CaptureOutcome]


def subprocess_runner(argv: Sequence[str]) -> CaptureOutcome:
    """Run one profiled command, measuring wall time around the subprocess."""
    start = time.perf_counter()
    proc = subprocess.run(argv, capture_output=True)
    wall_ms = (time.perf_counter() - start) * 1000.0
    if proc.returncode not in SUCCESSFUL_SCAN_EXITS:
        stderr = proc.stderr.decode("utf-8", "replace")[-2000:]
        raise ProfileCaptureError(
            f"profiled command exited {proc.returncode}: {shlex.join(argv)}\n"
            f"{stderr}"
        )
    return CaptureOutcome(exit_code=proc.returncode, wall_ms=wall_ms)


def capture_profiled_run(
    *,
    binary: str | pathlib.Path,
    scan_args: Sequence[str],
    profile_path: str | pathlib.Path,
    runner: CaptureRunner = subprocess_runner,
) -> tuple[TrialOutcome, ProfileArtifact]:
    """Run one binary with profile capture and bind the artifact by digest."""
    artifact_path = pathlib.Path(profile_path)
    artifact_path.parent.mkdir(parents=True, exist_ok=True)
    argv = [str(binary), *scan_args, PROFILE_OUT_FLAG, str(artifact_path)]
    outcome = runner(argv)
    if outcome.exit_code not in SUCCESSFUL_SCAN_EXITS:
        raise ProfileCaptureError(
            f"profiled command exited {outcome.exit_code}: {shlex.join(argv)}; "
            f"successful scan exits are {sorted(SUCCESSFUL_SCAN_EXITS)}"
        )
    if not artifact_path.exists():
        raise ProfileCaptureError(
            f"profiled command exited {outcome.exit_code} but wrote no artifact at "
            f"{artifact_path}; the binary lacks {PROFILE_OUT_FLAG} support"
        )
    artifact = artifact_for(artifact_path)
    return TrialOutcome(wall_ms=outcome.wall_ms, profile=artifact), artifact


@dataclass(frozen=True)
class PairedProfiles:
    """Both halves of one control/candidate profile capture."""

    control: ProfileArtifact
    candidate: ProfileArtifact


def capture_pair(
    *,
    control_binary: str | pathlib.Path,
    candidate_binary: str | pathlib.Path,
    scan_args: Sequence[str],
    workload: str,
    out_dir: str | pathlib.Path,
    runner: CaptureRunner = subprocess_runner,
) -> PairedProfiles:
    """Capture one profile per side of the pair into ``out_dir``."""
    out = pathlib.Path(out_dir)
    artifacts: dict[str, ProfileArtifact] = {}
    binaries = {"control": control_binary, "candidate": candidate_binary}
    for role in ("control", "candidate"):
        profile_path = out / f"{role}-{workload}-profile.json"
        _, artifact = capture_profiled_run(
            binary=binaries[role],
            scan_args=scan_args,
            profile_path=profile_path,
            runner=runner,
        )
        artifacts[role] = artifact
    return PairedProfiles(control=artifacts["control"], candidate=artifacts["candidate"])
