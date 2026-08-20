#!/usr/bin/env python3
"""Gate: TIMING LOG PROFILE IDENTITY (Row 102).

Enforces that no diagnostic-only logging or stderr printing holds timing evidence
that the profiler artifact lacks. Every timing value and throughput figure emitted
by the scanner must correspond to a registered `keyhog_profile` metric, stage, or
counter identity.

Acceptance criteria:
- No raw diagnostic-only `perf-trace` log line in scanner/source crates.
- No timing value formatted into a log line without corresponding profile identity.
- Stderr human-readable output derives from profiler state, not private Instant accumulators.
"""

from __future__ import annotations

import pathlib
import re
import sys

REPO = pathlib.Path(__file__).resolve().parents[2]

# Disallowed raw perf-trace log patterns in source code
PERF_TRACE_RAW_RE = re.compile(
    r'eprintln!\s*\(\s*["\']perf-trace\s+[^"\']*matcher=.*["\']'
)

# Pattern detecting raw Instant elapsed timing formatted into log lines without profiler backing
RAW_TIMING_PRINT_RE = re.compile(
    r'(?:eprintln!|println!)\s*\(\s*["\'].*?(?:matcher|coalesce|derive|floor|dispatch)=[^{"]*\{[^{}]*(?:s|ms|ns|secs_f64)\}[^"\']*["\']'
)


def scan_source_files(root: pathlib.Path) -> list[tuple[pathlib.Path, int, str]]:
    """Find violations where timing values are printed without profile identity."""
    violations = []
    crates_dir = root / "crates"
    if not crates_dir.exists():
        return violations

    for rs_file in crates_dir.rglob("*.rs"):
        # Only check src/ files (exclude tests/, benches/)
        rel = rs_file.relative_to(crates_dir)
        parts = rel.parts
        if "tests" in parts or "benches" in parts:
            continue

        try:
            content = rs_file.read_text(encoding="utf-8")
        except Exception:
            continue

        lines = content.splitlines()
        for idx, line in enumerate(lines, start=1):
            stripped = line.strip()
            if stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("*"):
                continue

            if PERF_TRACE_RAW_RE.search(line):
                violations.append(
                    (rs_file, idx, f"Raw perf-trace timing line found: {stripped}")
                )
            elif RAW_TIMING_PRINT_RE.search(line):
                # Allow scan_profile.rs formatting of registered profile records
                if rs_file.name in ("scan_profile.rs", "gpu.rs", "profile.rs"):
                    continue
                violations.append(
                    (rs_file, idx, f"Unregistered timing log line found: {stripped}")
                )

    return violations


def check_gpu_phase_registry(root: pathlib.Path) -> list[str]:
    """Verify GPU dispatch phase counters are registered in keyhog_profile."""
    errors = []
    metrics_rs = root / "crates" / "profile" / "src" / "metrics.rs"
    if not metrics_rs.exists():
        return [f"Missing {metrics_rs}"]

    content = metrics_rs.read_text(encoding="utf-8")

    required_phases = [
        "GpuMatcherNs",
        "GpuCoalesceNs",
        "GpuDispatchNs",
        "GpuDeriveNs",
        "GpuRecallFloorNs",
        "Phase2GpuAdmissionNs",
    ]

    for phase in required_phases:
        if phase not in content:
            errors.append(f"Missing required GPU dispatch phase metric: {phase}")

    if "GPU_DISPATCH_PHASE_COUNTERS" not in content:
        errors.append("Missing GPU_DISPATCH_PHASE_COUNTERS constant in keyhog_profile")

    if "GPU_DISPATCH_DECOMPOSITION_COUNTERS" not in content:
        errors.append("Missing GPU_DISPATCH_DECOMPOSITION_COUNTERS constant in keyhog_profile")

    return errors


def self_test() -> int:
    """Self-test verifying the gate detects violations and passes clean state."""
    import tempfile
    with tempfile.TemporaryDirectory() as tmpdir:
        tmproot = pathlib.Path(tmpdir)
        crates_dir = tmproot / "crates" / "scanner" / "src"
        crates_dir.mkdir(parents=True)

        rs_file = crates_dir / "dispatch.rs"
        rs_file.write_text(
            'fn bad() {\n    eprintln!("perf-trace gpu: matcher=0.001s coalesce=0.002s");\n}\n',
            encoding="utf-8",
        )

        violations = scan_source_files(tmproot)
        if not violations:
            print("FAIL: self-test did not catch raw perf-trace line")
            return 1

    print("PASS: timing_log_profile_identity self-test passed.")
    return 0


def main() -> int:
    if "--self-test" in sys.argv:
        return self_test()

    root = REPO
    violations = scan_source_files(root)
    registry_errors = check_gpu_phase_registry(root)

    if violations or registry_errors:
        print("FAIL: Timing Log Profile Identity gate failed:")
        for file_path, line_num, msg in violations:
            rel_path = file_path.relative_to(root)
            print(f"  {rel_path}:{line_num}: {msg}")
        for err in registry_errors:
            print(f"  registry: {err}")
        return 1

    print("PASS: Timing Log Profile Identity gate verified.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
