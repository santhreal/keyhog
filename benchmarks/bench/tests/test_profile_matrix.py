"""Locks the nightly profiling matrix contract and plan expansion."""

import pathlib

import pytest

from bench.profile_matrix import (
    MatrixError,
    load_matrix,
    plan_jobs,
)

_BENCHMARKS = pathlib.Path(__file__).resolve().parents[2]


def test_load_committed_nightly_matrix():
    """The committed matrix is what the nightly run expands; freeze its exact
    devices, workloads, and trial plans."""
    matrix = load_matrix(_BENCHMARKS / "profile-matrix" / "nightly.toml")
    assert matrix.schema_version == 1
    assert matrix.cadence == "nightly"
    assert [d.device_id for d in matrix.devices] == [
        "linux-x86_64-desktop",
        "linux-x86_64-hosted-4core",
        "linux-arm64-hosted",
        "macos-arm64-laptop",
        "windows-x86_64-laptop",
    ]
    assert matrix.devices[1].device_class == "hosted"
    assert matrix.devices[3].os == "macos"
    assert matrix.devices[3].arch == "aarch64"
    assert [w.name for w in matrix.workloads] == ["mirror", "creddata", "homefield"]
    mirror = matrix.workloads[0]
    assert mirror.corpus == "mirror"
    assert mirror.config_id == "simd-nocache-nodaemon-full"
    assert mirror.budgets == "profile-gates/budgets.toml"
    assert (mirror.cold, mirror.warm, mirror.steady) == (3, 3, 5)
    assert mirror.seed == 20260803
    homefield = matrix.workloads[2]
    assert (homefield.cold, homefield.warm, homefield.steady) == (2, 2, 5)


def test_plan_jobs_deterministic_full_cross_product():
    """The plan is the sorted device-major cross product; CI must dispatch
    the same job ids on every expansion."""
    matrix = load_matrix(_BENCHMARKS / "profile-matrix" / "nightly.toml")
    jobs = plan_jobs(matrix)
    assert len(jobs) == 15
    assert [j.job_id for j in jobs] == sorted(j.job_id for j in jobs)
    assert jobs[0].job_id == "linux-arm64-hosted/creddata"
    assert jobs[-1].job_id == "windows-x86_64-laptop/mirror"
    again = plan_jobs(load_matrix(_BENCHMARKS / "profile-matrix" / "nightly.toml"))
    assert [j.job_id for j in again] == [j.job_id for j in jobs]


def test_plan_job_payload_carries_trial_plan():
    """Each job carries the full trial plan and seed so the runner needs no
    hidden defaults."""
    matrix = load_matrix(_BENCHMARKS / "profile-matrix" / "nightly.toml")
    job = next(j for j in plan_jobs(matrix) if j.job_id == "linux-x86_64-desktop/mirror")
    payload = job.to_json()
    assert payload["device"] == {
        "id": "linux-x86_64-desktop", "os": "linux", "arch": "x86_64",
        "class": "desktop",
    }
    assert payload["workload"]["cold"] == 3
    assert payload["workload"]["steady"] == 5
    assert payload["workload"]["seed"] == 20260803
    assert payload["workload"]["budgets"] == "profile-gates/budgets.toml"


def _write(tmp_path, text):
    path = tmp_path / "matrix.toml"
    path.write_text(text)
    return path


_MINIMAL_DEVICE = '[[device]]\nid = "d1"\nos = "linux"\narch = "x86_64"\nclass = "hosted"\n'
_MINIMAL_WORKLOAD = (
    '[[workload]]\nname = "w1"\ncorpus = "mirror"\n'
    'config_id = "simd-nocache-nodaemon-full"\nbudgets = "b.toml"\n'
    "cold = 1\nwarm = 0\nsteady = 1\nseed = 1\n"
)


def test_matrix_rejects_bad_schema_version(tmp_path):
    """A matrix from another schema version is undecidable."""
    path = _write(tmp_path, "schema_version = 2\ncadence = \"nightly\"\n"
                  + _MINIMAL_DEVICE + _MINIMAL_WORKLOAD)
    with pytest.raises(MatrixError, match="schema_version"):
        load_matrix(path)


def test_matrix_requires_devices_and_workloads(tmp_path):
    """An empty matrix would expand to a silently empty nightly run."""
    path = _write(tmp_path, "schema_version = 1\ncadence = \"nightly\"\n")
    with pytest.raises(MatrixError, match="device"):
        load_matrix(path)
    path = _write(tmp_path, "schema_version = 1\ncadence = \"nightly\"\n"
                  + _MINIMAL_DEVICE)
    with pytest.raises(MatrixError, match="workload"):
        load_matrix(path)


def test_matrix_rejects_duplicate_ids(tmp_path):
    """Duplicate device or workload ids make job ids collide."""
    path = _write(tmp_path, "schema_version = 1\ncadence = \"nightly\"\n"
                  + _MINIMAL_DEVICE + _MINIMAL_DEVICE + _MINIMAL_WORKLOAD)
    with pytest.raises(MatrixError, match="duplicate device"):
        load_matrix(path)
    path = _write(tmp_path, "schema_version = 1\ncadence = \"nightly\"\n"
                  + _MINIMAL_DEVICE + _MINIMAL_WORKLOAD + _MINIMAL_WORKLOAD)
    with pytest.raises(MatrixError, match="duplicate workload"):
        load_matrix(path)


def test_matrix_rejects_zero_trial_workload(tmp_path):
    """A workload with no trials would produce an empty, unverifiable run."""
    workload = _MINIMAL_WORKLOAD.replace("cold = 1", "cold = 0").replace(
        "steady = 1", "steady = 0"
    )
    path = _write(tmp_path, "schema_version = 1\ncadence = \"nightly\"\n"
                  + _MINIMAL_DEVICE + workload)
    with pytest.raises(MatrixError, match="at least one trial"):
        load_matrix(path)


def test_matrix_rejects_unknown_fields(tmp_path):
    """Unknown fields hide typos that silently drop a lane from the matrix."""
    device = _MINIMAL_DEVICE.replace('class = "hosted"',
                                     'class = "hosted"\nregion = "eu"')
    path = _write(tmp_path, "schema_version = 1\ncadence = \"nightly\"\n"
                  + device + _MINIMAL_WORKLOAD)
    with pytest.raises(MatrixError, match="unknown fields"):
        load_matrix(path)
