import pytest

from bench import hardware


def test_affinity_cores_captures_current_process_mask(monkeypatch):
    """Guards affinity cores captures current process mask; prevents this evidence regression from false-passing or crashing."""
    monkeypatch.setattr(hardware.os, "sched_getaffinity", lambda pid: {1, 3, 5, 7})

    assert hardware._affinity_cores() == 4


def test_affinity_cores_fails_closed(monkeypatch):
    """Guards affinity cores fails closed; prevents this evidence regression from false-passing or crashing."""
    def unavailable(pid):
        raise OSError("not supported")

    monkeypatch.setattr(hardware.os, "sched_getaffinity", unavailable)

    assert hardware._affinity_cores() == 0


def test_cgroup_quota_cores_reads_exact_finite_v2_limit(tmp_path):
    """A finite ``cpu.max`` quota must retain its exact four-core allocation."""
    cpu_max = tmp_path / "cpu.max"
    cpu_max.write_text("400000 100000\n", encoding="utf-8")

    assert hardware._cgroup_quota_cores(cpu_max) == 4.0


def test_cgroup_quota_cores_distinguishes_genuine_unbounded_v2_limit(tmp_path):
    """The documented ``max PERIOD`` form is unbounded, not missing or malformed."""
    cpu_max = tmp_path / "cpu.max"
    cpu_max.write_text("max 100000\n", encoding="utf-8")

    assert hardware._cgroup_quota_cores(cpu_max) == hardware.CGROUP_QUOTA_UNBOUNDED


@pytest.mark.parametrize(
    "contents",
    ["400000 0\n", "0 100000\n", "malformed\n", "max malformed\n", "max 100000 extra\n"],
)
def test_cgroup_quota_cores_marks_invalid_v2_data_unknown(tmp_path, contents):
    """Malformed or impossible quota text must not be promoted to unbounded."""
    cpu_max = tmp_path / "cpu.max"
    cpu_max.write_text(contents, encoding="utf-8")

    assert hardware._cgroup_quota_cores(cpu_max) == hardware.CGROUP_QUOTA_UNKNOWN


def test_cgroup_quota_cores_marks_missing_controllers_unknown(tmp_path):
    """Missing v2 and v1 controllers must remain unknown, never unbounded."""
    assert (
        hardware._cgroup_quota_cores(tmp_path / "missing", cpu_v1_roots=())
        == hardware.CGROUP_QUOTA_UNKNOWN
    )
    assert hardware._cgroup_quota_cores(
        tmp_path / "missing",
        cpu_v1_roots=(tmp_path / "also-missing",),
    ) == hardware.CGROUP_QUOTA_UNKNOWN


def test_cgroup_quota_cores_reads_exact_finite_v1_limit(tmp_path):
    """A v1-only hosted runner must retain its exact four-core CPU allocation."""
    root = tmp_path / "cpu"
    root.mkdir()
    (root / "cpu.cfs_quota_us").write_text("400000\n", encoding="utf-8")
    (root / "cpu.cfs_period_us").write_text("100000\n", encoding="utf-8")

    assert hardware._cgroup_quota_cores(
        tmp_path / "missing-v2",
        cpu_v1_roots=(root,),
    ) == 4.0


def test_cgroup_quota_cores_distinguishes_genuine_unbounded_v1_limit(tmp_path):
    """The documented v1 ``-1`` quota must remain distinct from missing evidence."""
    root = tmp_path / "cpu"
    root.mkdir()
    (root / "cpu.cfs_quota_us").write_text("-1\n", encoding="utf-8")
    (root / "cpu.cfs_period_us").write_text("100000\n", encoding="utf-8")

    assert (
        hardware._cgroup_quota_cores(
            tmp_path / "missing-v2",
            cpu_v1_roots=(root,),
        )
        == hardware.CGROUP_QUOTA_UNBOUNDED
    )


@pytest.mark.parametrize(("quota", "period"), [("0", "100000"), ("400000", "0"), ("bad", "100000")])
def test_cgroup_quota_cores_marks_invalid_v1_data_unknown(tmp_path, quota, period):
    """Malformed or impossible v1 quota data must never become usable evidence."""
    root = tmp_path / "cpu"
    root.mkdir()
    (root / "cpu.cfs_quota_us").write_text(f"{quota}\n", encoding="utf-8")
    (root / "cpu.cfs_period_us").write_text(f"{period}\n", encoding="utf-8")

    assert (
        hardware._cgroup_quota_cores(
            tmp_path / "missing-v2",
            cpu_v1_roots=(root,),
        )
        == hardware.CGROUP_QUOTA_UNKNOWN
    )


def test_cgroup_quota_cores_marks_unreadable_controller_unknown(monkeypatch, tmp_path):
    """An unreadable controller must fail closed instead of masquerading as unbounded."""
    cpu_max = tmp_path / "cpu.max"
    cpu_max.write_text("max 100000\n", encoding="utf-8")

    def deny_read(path, *, encoding):
        raise PermissionError("denied")

    monkeypatch.setattr(hardware.pathlib.Path, "read_text", deny_read)
    assert hardware._cgroup_quota_cores(cpu_max) == hardware.CGROUP_QUOTA_UNKNOWN


def test_missing_nvidia_smi_records_incomplete_inventory(monkeypatch):
    """Tool absence records an unavailable NVIDIA query, never physical no-accelerator."""
    monkeypatch.setattr(hardware.shutil, "which", lambda command: None)

    assert hardware.accelerator_inventory() == {
        "source": "nvidia-smi",
        "status": hardware.ACCELERATOR_INVENTORY_UNAVAILABLE,
        "devices": [],
    }


def test_nvidia_smi_observations_preserve_all_reported_devices(monkeypatch):
    """A successful scoped query records every reported NVIDIA name and VRAM value."""
    monkeypatch.setattr(hardware.shutil, "which", lambda command: "/usr/bin/nvidia-smi")
    monkeypatch.setattr(
        hardware.subprocess,
        "run",
        lambda *args, **kwargs: hardware.subprocess.CompletedProcess(
            args[0],
            0,
            stdout="NVIDIA One, 8192\nNVIDIA Two, 16384\n",
            stderr="",
        ),
    )

    assert hardware.accelerator_inventory() == {
        "source": "nvidia-smi",
        "status": hardware.ACCELERATOR_INVENTORY_OBSERVED,
        "devices": [
            {"name": "NVIDIA One", "vram_mb": 8192},
            {"name": "NVIDIA Two", "vram_mb": 16384},
        ],
    }


def test_capture_does_not_cache_process_scoped_cpu_identity(monkeypatch):
    """Guards capture does not cache process scoped cpu identity; prevents this evidence regression from false-passing or crashing."""
    affinity = iter([2, 4])
    monkeypatch.setattr(hardware, "_hostname_hash", lambda: "host")
    monkeypatch.setattr(hardware, "_cpu_model", lambda: "cpu")
    monkeypatch.setattr(hardware, "_ram_mb", lambda: 1024)
    monkeypatch.setattr(hardware, "_gpu", lambda: ("", 0))
    monkeypatch.setattr(hardware, "_affinity_cores", lambda: next(affinity))
    monkeypatch.setattr(hardware, "_cgroup_quota_cores", lambda: 4.0)

    assert hardware.capture().affinity_cores == 2
    assert hardware.capture().affinity_cores == 4
