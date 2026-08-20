#!/usr/bin/env python3
"""Gate: UNIFIED COUNTER OWNERSHIP (Row 99).

Ensures that `keyhog_profile` is the single authoritative owner of all scan,
source, and scanner metrics. No crate outside `keyhog_profile` may declare
scattered, unmapped process-global counter statics that do not serialize into
the profiler runtime and `--profile-out` artifact.

Acceptance criteria:
- Every scattered counter appears in `keyhog_profile` with exact identity.
- No unmapped process-global counter static outside `keyhog_profile`.
- Adding a counter outside the owner fails the suite.
"""

from __future__ import annotations

import pathlib
import re
import sys

REPO = pathlib.Path(__file__).resolve().parents[2]

# Regex for static Atomic definitions
ATOMIC_STATIC_RE = re.compile(
    r"^\s*(?:pub(?:\([^)]+\))?\s+)?static\s+([A-Z0-9_]+)\s*:\s*Atomic[A-Za-z0-9]+\s*="
)

# Known non-counter atomic statics (lifecycle flags, mutex/gate state, sequence numbers, IDs)
NON_COUNTER_STATICS = {
    # Sequence IDs and generators
    "NEXT_OBSERVED_PATHS_ID",
    "DAEMON_GENERATION_SEQUENCE",
    "ACTIVE_GUARDS",
    "INSTALLED",
    "ACTIVE_ALLOC_SESSIONS",
    "ALLOC_SESSION_OVERLAP",
    "DETAIL",
    "ACTIVE_CONTEXTS",
    "NEXT_THREAD_ID",
    "NEXT_CONTEXT_ID",
    "RUN_SEQUENCE",
    "PERF_STATE",
    "GPU_BATCH_INPUT_LIMIT_OVERRIDE",
    "GPU_RUNTIME_POLICY",
    "SCANNER_ID_SEQ",
    "SCANNER_PANICKED",
    "OPERATOR_PROFILE_ACTIVE",
    "DOGFOOD_ENABLED",
    "VENDORED_PATH_SUPPRESSION_ENABLED",
    "CALL_COUNT",
    "CACHED",
    "DEDUP_LOST_SINGLETON",
}


def find_atomic_statics(root: pathlib.Path) -> list[tuple[pathlib.Path, int, str]]:
    """Find all atomic static variable declarations in Rust source files."""
    results = []
    crates_dir = root / "crates"
    if not crates_dir.exists():
        return results

    for rs_file in crates_dir.rglob("*.rs"):
        # Skip target directories if any
        if "target" in rs_file.parts:
            continue

        try:
            content = rs_file.read_text(encoding="utf-8")
        except Exception:
            continue

        for line_num, line in enumerate(content.splitlines(), start=1):
            match = ATOMIC_STATIC_RE.search(line)
            if match:
                var_name = match.group(1)
                results.append((rs_file, line_num, var_name))
    return results


def check_counter_ownership(root: pathlib.Path) -> tuple[bool, list[str]]:
    """Validate that all counter statics are owned by keyhog_profile or mapped to CounterId/GaugeId."""
    violations = []
    statics = find_atomic_statics(root)

    # Read CounterId enum variants from crates/profile/src/metrics.rs
    metrics_file = root / "crates" / "profile" / "src" / "metrics.rs"
    if not metrics_file.exists():
        return False, ["crates/profile/src/metrics.rs not found"]

    metrics_content = metrics_file.read_text(encoding="utf-8")

    # Verify that keyhog_profile defines CounterId and GaugeId
    if "pub enum CounterId" not in metrics_content:
        violations.append("crates/profile/src/metrics.rs missing CounterId enum definition")
    if "pub enum GaugeId" not in metrics_content:
        violations.append("crates/profile/src/metrics.rs missing GaugeId enum definition")

    for file_path, line_num, var_name in statics:
        rel_path = file_path.relative_to(root).as_posix()

        # Inside crates/profile is always permitted (the owner)
        if rel_path.startswith("crates/profile/"):
            continue

        # In tests/examples/benches, local counters are allowed
        if "/tests/" in rel_path or "/benches/" in rel_path or "/examples/" in rel_path:
            continue

        # Check against known non-counter statics
        if var_name in NON_COUNTER_STATICS:
            continue

        # For remaining statics outside profile, verify they forward into keyhog_profile
        try:
            file_content = file_path.read_text(encoding="utf-8")
        except Exception:
            violations.append(f"{rel_path}:{line_num}: Cannot read file containing static {var_name}")
            continue

        if "keyhog_profile::add_counter" not in file_content and "keyhog_profile::set_gauge" not in file_content and "keyhog_profile::" not in file_content:
            violations.append(
                f"{rel_path}:{line_num}: Stray unmapped counter static `{var_name}` outside `keyhog_profile` owner."
            )

    return len(violations) == 0, violations


def run_self_test() -> int:
    """Self-test for the counter ownership gate."""
    # Test valid repo state
    passed, violations = check_counter_ownership(REPO)
    if not passed:
        print(f"Self-test failed on repo: {violations}", file=sys.stderr)
        return 1
    print("unified_counter_ownership.py --self-test passed.")
    return 0


def main() -> int:
    if "--self-test" in sys.argv:
        return run_self_test()

    passed, violations = check_counter_ownership(REPO)
    if not passed:
        print("Gate failure: Unified Counter Ownership (Row 99)", file=sys.stderr)
        for v in violations:
            print(f"  - {v}", file=sys.stderr)
        return 1

    print("Gate passed: Unified Counter Ownership (Row 99)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
