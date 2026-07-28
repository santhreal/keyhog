"""Capture the host hardware axis for a benchmark run.

Every probe is best-effort and never raises. Accelerator inventory explicitly
records when the NVIDIA query is unavailable; an empty GPU name alone therefore
does not assert physical accelerator absence. The same code path works on Linux
desktop, santhserver, the Windows ThinkPad (via WSL/Git Bash), and macOS. The
result feeds :class:`bench.schema.Host` so runs from every machine aggregate
into one OS/CPU/GPU matrix.

``hostname_hash`` is a truncated SHA-256 of the hostname, stable per
machine, but not the raw name (keeps committed result files free of bare
hostnames while still grouping a host's runs).
"""

from __future__ import annotations

import hashlib
import os
import pathlib
import platform
import re
import shutil
import subprocess

from .schema import Host

CGROUP_QUOTA_UNBOUNDED = "unbounded"
CGROUP_QUOTA_UNKNOWN = "unknown"
ACCELERATOR_INVENTORY_OBSERVED = "nvidia-smi-observed"
ACCELERATOR_INVENTORY_UNAVAILABLE = "nvidia-smi-unavailable"


def _hostname_hash() -> str:
    name = platform.node() or os.environ.get("HOSTNAME", "") or "unknown"
    return hashlib.sha256(name.encode("utf-8", "replace")).hexdigest()[:12]


def _cpu_model() -> str:
    # Linux: /proc/cpuinfo "model name"; macOS: sysctl; fallback: platform.
    try:
        with open("/proc/cpuinfo") as f:
            for line in f:
                if line.lower().startswith("model name"):
                    return line.split(":", 1)[1].strip()
    except OSError:
        pass
    if shutil.which("sysctl"):
        try:
            out = subprocess.run(
                ["sysctl", "-n", "machdep.cpu.brand_string"],
                capture_output=True, text=True, timeout=5, check=False,
            )
            if out.stdout.strip():
                return out.stdout.strip()
        except (OSError, subprocess.SubprocessError):
            pass
    return platform.processor() or platform.machine() or ""


def _ram_mb() -> int:
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith("MemTotal:"):
                    kb = int(line.split()[1])
                    return kb // 1024
    except (OSError, ValueError, IndexError):
        pass
    # macOS / BSD: sysctl hw.memsize (bytes)
    if shutil.which("sysctl"):
        try:
            out = subprocess.run(
                ["sysctl", "-n", "hw.memsize"],
                capture_output=True, text=True, timeout=5, check=False,
            )
            if out.stdout.strip().isdigit():
                return int(out.stdout.strip()) // (1024 * 1024)
        except (OSError, subprocess.SubprocessError):
            pass
    return 0


def _nvidia_inventory() -> tuple[str, tuple[tuple[str, int], ...]]:
    """Return a best-effort NVIDIA inventory and the scope of that observation."""
    if shutil.which("nvidia-smi") is None:
        return (ACCELERATOR_INVENTORY_UNAVAILABLE, ())
    try:
        out = subprocess.run(
            ["nvidia-smi", "--query-gpu=name,memory.total",
             "--format=csv,noheader,nounits"],
            capture_output=True, text=True, timeout=10, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return (ACCELERATOR_INVENTORY_UNAVAILABLE, ())
    if out.returncode != 0:
        return (ACCELERATOR_INVENTORY_UNAVAILABLE, ())
    devices: list[tuple[str, int]] = []
    for line in (out.stdout or "").strip().splitlines():
        parts = [part.strip() for part in line.rsplit(",", 1)]
        if len(parts) != 2 or not parts[0] or re.fullmatch(r"\d+", parts[1]) is None:
            return (ACCELERATOR_INVENTORY_UNAVAILABLE, ())
        devices.append((parts[0], int(parts[1])))
    return (ACCELERATOR_INVENTORY_OBSERVED, tuple(devices))


def accelerator_inventory() -> dict[str, object]:
    """Describe only what the best-effort NVIDIA query actually observed."""
    status, devices = _nvidia_inventory()
    return {
        "source": "nvidia-smi",
        "status": status,
        "devices": [
            {"name": name, "vram_mb": vram_mb}
            for name, vram_mb in devices
        ],
    }


def _gpu() -> tuple[str, int]:
    """Return the first NVIDIA GPU observed, without treating an empty result as absence."""
    _, devices = _nvidia_inventory()
    return devices[0] if devices else ("", 0)


def _affinity_cores() -> int:
    """Return the CPUs available to this process, or zero when not provable."""
    try:
        affinity = os.sched_getaffinity(0)
    except (AttributeError, OSError):
        return 0
    return len(affinity) if affinity else 0


def _parse_cpu_max(path: pathlib.Path) -> tuple[bool, float | str]:
    """Parse one cgroup v2 quota file and distinguish absence from invalid data."""
    try:
        fields = path.read_text(encoding="utf-8").split()
    except FileNotFoundError:
        return False, CGROUP_QUOTA_UNKNOWN
    except (OSError, UnicodeError):
        return True, CGROUP_QUOTA_UNKNOWN
    if len(fields) != 2:
        return True, CGROUP_QUOTA_UNKNOWN
    try:
        period = int(fields[1])
    except ValueError:
        return True, CGROUP_QUOTA_UNKNOWN
    if period <= 0:
        return True, CGROUP_QUOTA_UNKNOWN
    if fields[0] == "max":
        return True, CGROUP_QUOTA_UNBOUNDED
    try:
        quota = int(fields[0])
    except ValueError:
        return True, CGROUP_QUOTA_UNKNOWN
    if quota <= 0:
        return True, CGROUP_QUOTA_UNKNOWN
    return True, quota / period


def _current_v2_quota(
    cgroup_root: pathlib.Path,
    proc_self_cgroup: pathlib.Path,
) -> tuple[bool, float | str]:
    """Resolve the process cgroup and apply the tightest observable ancestor quota."""
    try:
        membership = proc_self_cgroup.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        return False, CGROUP_QUOTA_UNKNOWN
    except (OSError, UnicodeError):
        return True, CGROUP_QUOTA_UNKNOWN
    unified = [line.split(":", 2)[2] for line in membership if line.startswith("0::") and line.count(":") == 2]
    if not unified:
        return False, CGROUP_QUOTA_UNKNOWN
    if len(unified) != 1:
        return True, CGROUP_QUOTA_UNKNOWN
    relative = pathlib.PurePosixPath(unified[0].lstrip("/"))
    if any(part in ("", ".", "..") for part in relative.parts):
        return True, CGROUP_QUOTA_UNKNOWN
    current = cgroup_root.joinpath(*relative.parts)
    finite: list[float] = []
    observed = False
    while True:
        exists, quota = _parse_cpu_max(current / "cpu.max")
        if exists:
            observed = True
            if quota == CGROUP_QUOTA_UNKNOWN:
                return True, CGROUP_QUOTA_UNKNOWN
            if isinstance(quota, float):
                finite.append(quota)
        if current == cgroup_root:
            break
        if cgroup_root not in current.parents:
            return True, CGROUP_QUOTA_UNKNOWN
        current = current.parent
    if not observed:
        return True, CGROUP_QUOTA_UNKNOWN
    return True, min(finite) if finite else CGROUP_QUOTA_UNBOUNDED


def _cgroup_quota_cores(
    cpu_max: str | pathlib.Path | None = None,
    *,
    cgroup_root: str | pathlib.Path = "/sys/fs/cgroup",
    proc_self_cgroup: str | pathlib.Path = "/proc/self/cgroup",
    cpu_v1_roots: tuple[str | pathlib.Path, ...] = (
        "/sys/fs/cgroup/cpu",
        "/sys/fs/cgroup/cpu,cpuacct",
    ),
) -> float | str:
    """Return the effective finite v2/v1 quota or an authenticated unbounded state."""
    if cpu_max is None:
        observed, quota = _current_v2_quota(
            pathlib.Path(cgroup_root),
            pathlib.Path(proc_self_cgroup),
        )
    else:
        observed, quota = _parse_cpu_max(pathlib.Path(cpu_max))
    if observed:
        return quota

    for root_value in cpu_v1_roots:
        root = pathlib.Path(root_value)
        try:
            quota_text = (root / "cpu.cfs_quota_us").read_text(encoding="utf-8").strip()
            period_text = (root / "cpu.cfs_period_us").read_text(encoding="utf-8").strip()
        except FileNotFoundError:
            continue
        except (OSError, UnicodeError):
            return CGROUP_QUOTA_UNKNOWN
        try:
            quota_value = int(quota_text)
            period = int(period_text)
        except ValueError:
            return CGROUP_QUOTA_UNKNOWN
        if period <= 0:
            return CGROUP_QUOTA_UNKNOWN
        if quota_value == -1:
            return CGROUP_QUOTA_UNBOUNDED
        return quota_value / period if quota_value > 0 else CGROUP_QUOTA_UNKNOWN
    return CGROUP_QUOTA_UNKNOWN


def _capture() -> Host:
    """Probe the current host without caching process-scoped CPU identity."""
    gpu_name, gpu_vram = _gpu()
    return Host(
        hostname_hash=_hostname_hash(),
        os=f"{platform.system()} {platform.release()}".strip(),
        kernel=platform.version(),
        cpu=_cpu_model(),
        cores=os.cpu_count() or 0,
        affinity_cores=_affinity_cores(),
        cgroup_quota_cores=_cgroup_quota_cores(),
        ram_mb=_ram_mb(),
        gpu=gpu_name,
        gpu_vram_mb=gpu_vram,
    )


def capture() -> Host:
    """Probe the current host into a :class:`Host`. Never raises."""
    return _capture()


if __name__ == "__main__":
    import json
    print(json.dumps(capture().to_json(), indent=2))
