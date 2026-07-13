"""Capture the host hardware axis for a benchmark run.

Every probe is best-effort and never raises: an absent ``nvidia-smi`` or an
unreadable ``/proc`` simply leaves that field empty, so the same code path
works on Linux desktop, santhserver, the Windows ThinkPad (via WSL/Git
Bash), and macOS. The result feeds :class:`bench.schema.Host` so runs from
every machine aggregate into one OS/CPU/GPU matrix.

``hostname_hash`` is a truncated SHA-256 of the hostname, stable per
machine, but not the raw name (keeps committed result files free of bare
hostnames while still grouping a host's runs).
"""

from __future__ import annotations

import hashlib
import os
import platform
import re
import shutil
import subprocess
from dataclasses import replace
from functools import lru_cache

from .schema import Host


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


def _gpu() -> tuple[str, int]:
    """Return (gpu_name, vram_mb) via nvidia-smi, or ("", 0) if absent.

    A keyhog GPU-backend run is only meaningful where a CUDA device exists,
    so the perf/parity matrix needs this to label which rows actually
    exercised the GPU path (vs. silently degrading to SIMD).
    """
    if shutil.which("nvidia-smi") is None:
        return ("", 0)
    try:
        out = subprocess.run(
            ["nvidia-smi", "--query-gpu=name,memory.total",
             "--format=csv,noheader,nounits"],
            capture_output=True, text=True, timeout=10, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return ("", 0)
    line = (out.stdout or "").strip().splitlines()
    if not line:
        return ("", 0)
    # First GPU only; "NVIDIA GeForce RTX 5090, 32607"
    parts = [p.strip() for p in line[0].split(",")]
    name = parts[0] if parts else ""
    vram = 0
    if len(parts) > 1:
        m = re.search(r"\d+", parts[1])
        if m:
            vram = int(m.group(0))
    return (name, vram)


@lru_cache(maxsize=1)
def _capture() -> Host:
    """Probe the current host ONCE per process. Host hardware is invariant, but
    the probes spawn nvidia-smi (10s timeout) + sysctl and re-read /proc, and a
    perf-tier matrix asks for the host for every RunResult (build_result,
    _unavailable_result, results_dir), dozens of redundant probes without this."""
    gpu_name, gpu_vram = _gpu()
    return Host(
        hostname_hash=_hostname_hash(),
        os=f"{platform.system()} {platform.release()}".strip(),
        kernel=platform.version(),
        cpu=_cpu_model(),
        cores=os.cpu_count() or 0,
        ram_mb=_ram_mb(),
        gpu=gpu_name,
        gpu_vram_mb=gpu_vram,
    )


def capture() -> Host:
    """Probe the current host into a :class:`Host`. Never raises. Returns a fresh
    copy of the cached probe so a caller mutating its Host can't poison others."""
    return replace(_capture())


if __name__ == "__main__":
    import json
    print(json.dumps(capture().to_json(), indent=2))
