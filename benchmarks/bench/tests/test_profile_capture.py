"""Locks paired control/candidate profile capture behavior."""

import hashlib
import json

import pytest

from bench.profile_capture import (
    CaptureOutcome,
    ProfileCaptureError,
    capture_pair,
    capture_profiled_run,
)


def _profile_payload(run_id):
    return {
        "version": 5,
        "envelope": {
            "version": 1,
            "schema": "keyhog-profile",
            "schema_version": {"version": 1, "major": 2, "minor": 4},
        },
        "identity": {"version": 1, "run_id": run_id},
        "wall_time_ns": 1_000_000,
        "stages": [
            {"version": 1, "stage": "decode", "elapsed_ns": 600_000,
             "calls": 1, "attributed_ns": 600_000},
        ],
    }


def _runner(recorded, *, exit_code=0, write=True, wall_ms=12.5):
    """Fake capture runner: records argv, optionally writes the artifact."""
    def run(argv):
        recorded.append(list(argv))
        if write:
            profile_path = argv[argv.index("--profile-out") + 1]
            run_id = "control" if "control" in str(profile_path) else "candidate"
            with open(profile_path, "w") as handle:
                json.dump(_profile_payload(run_id), handle)
        return CaptureOutcome(exit_code=exit_code, wall_ms=wall_ms)

    return run


def test_capture_profiled_run_appends_flag_and_binds(tmp_path):
    """The runner must invoke the binary with --profile-out last and digest
    the exact bytes the binary wrote."""
    recorded = []
    outcome, artifact = capture_profiled_run(
        binary="/bin/keyhog",
        scan_args=["scan", "/corpus", "--no-daemon"],
        profile_path=tmp_path / "p.json",
        runner=_runner(recorded),
    )
    assert recorded == [[
        "/bin/keyhog", "scan", "/corpus", "--no-daemon",
        "--profile-out", str(tmp_path / "p.json"),
    ]]
    assert outcome.wall_ms == 12.5
    assert outcome.profile is artifact
    payload_bytes = (tmp_path / "p.json").read_bytes()
    assert artifact.sha256 == hashlib.sha256(payload_bytes).hexdigest()
    assert artifact.bytes == len(payload_bytes)


def test_capture_pair_stores_both_artifacts(tmp_path):
    """Both halves of the pair land beside the results with role-qualified
    names and independent digests."""
    recorded = []
    pair = capture_pair(
        control_binary="/bin/keyhog-control",
        candidate_binary="/bin/keyhog-candidate",
        scan_args=["scan", "/corpus"],
        workload="mirror",
        out_dir=tmp_path,
        runner=_runner(recorded),
    )
    control_path = tmp_path / "control-mirror-profile.json"
    candidate_path = tmp_path / "candidate-mirror-profile.json"
    assert control_path.exists()
    assert candidate_path.exists()
    assert pair.control.path == str(control_path)
    assert pair.candidate.path == str(candidate_path)
    assert pair.control.sha256 == hashlib.sha256(
        control_path.read_bytes()
    ).hexdigest()
    assert pair.candidate.sha256 == hashlib.sha256(
        candidate_path.read_bytes()
    ).hexdigest()
    assert pair.control.sha256 != pair.candidate.sha256
    assert len(recorded) == 2


def test_capture_nonzero_exit_is_hard_error(tmp_path):
    """A failed profiled run never yields a trial; the artifact contract
    forbids partial output, so there is nothing to salvage."""
    with pytest.raises(ProfileCaptureError, match="exited 3"):
        capture_profiled_run(
            binary="/bin/keyhog",
            scan_args=["scan"],
            profile_path=tmp_path / "p.json",
            runner=_runner([], exit_code=3, write=False),
        )
    assert not (tmp_path / "p.json").exists()


def test_capture_missing_artifact_is_hard_error(tmp_path):
    """Exit 0 with no artifact means the binary lacks --profile-out support;
    say so instead of recording an unprofiled run as profiled."""
    with pytest.raises(ProfileCaptureError, match="wrote no artifact"):
        capture_profiled_run(
            binary="/bin/keyhog",
            scan_args=["scan"],
            profile_path=tmp_path / "p.json",
            runner=_runner([], write=False),
        )


def test_capture_invalid_artifact_is_hard_error(tmp_path):
    """An artifact that fails envelope validation never gets a digest
    reference."""
    def bad_runner(argv):
        profile_path = argv[argv.index("--profile-out") + 1]
        with open(profile_path, "w") as handle:
            handle.write('{"envelope": {"schema": "other"}}')
        return CaptureOutcome(exit_code=0, wall_ms=1.0)

    with pytest.raises(Exception, match="envelope schema"):
        capture_profiled_run(
            binary="/bin/keyhog",
            scan_args=["scan"],
            profile_path=tmp_path / "p.json",
            runner=bad_runner,
        )


@pytest.mark.parametrize("exit_code", [1, 10, 13])
def test_capture_accepts_finding_and_coverage_scan_exits(tmp_path, exit_code):
    """WHY: KeyHog uses nonzero success exits for findings and coverage gaps; rejecting them made every finding-bearing canonical profile impossible to capture."""
    outcome, artifact = capture_profiled_run(
        binary="/bin/keyhog", scan_args=["scan"],
        profile_path=tmp_path / f"profile-{exit_code}.json",
        runner=_runner([], exit_code=exit_code),
    )
    assert outcome.wall_ms == 12.5
    assert artifact.bytes > 0
