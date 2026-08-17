#!/usr/bin/env python3
"""Gate #14: VACUOUS TESTS: capability-conditional tests must not skip silently.

A test whose assertions all sit behind a capability predicate (such as
`gpu_available()`, `warm_backend()`, or hardware probes) passes vacuously when
the capability is absent, reporting that absence as success.

This gate statically analyzes all test files across crates, detecting early
returns guarded by capability predicates, and requires that every such test:
  1. Arms required policies (e.g. `arm_policy_from_env()`, `require_gpu_or_panic`), OR
  2. Panics on missing capabilities when required by policy, OR
  3. Registers its skip outcome with a ledger/diagnostic mechanism.

Run: python3 scripts/gates/vacuous_tests.py   (exit 1 on a gap)
"""
from __future__ import annotations

import pathlib
import re
import sys

REPO = pathlib.Path(__file__).resolve().parents[2]

CAPABILITY_PREDICATES = [
    r"gpu_available\(\)",
    r"warm_backend\(",
    r"has_avx2\(\)",
    r"has_avx512\(\)",
    r"has_neon\(\)",
    r"io_uring_available",
    r"hyperscan_available",
]

# Patterns indicating that the test handles capability checks safely:
SAFE_HANDLERS = [
    r"arm_policy_from_env",
    r"require_gpu_or_panic",
    r"require_gpu_policy",
    r"gpu_required_by_policy",
    r"unavailable_gpu_self_test_report",
    r"PolicyGuard",
    r"require_gpu_preflight",
]


def check_test_content(content: str, path: str = "") -> list[str]:
    """Return violations where capability checks guard early returns with no safe handler."""
    violations = []
    lines = content.splitlines()

    # Look for functions containing capability checks
    fn_indices = [
        (i, line)
        for i, line in enumerate(lines)
        if line.strip().startswith("fn ") or " fn " in line
    ]

    for idx, (line_no, fn_line) in enumerate(fn_indices):
        end_idx = fn_indices[idx + 1][0] if idx + 1 < len(fn_indices) else len(lines)
        fn_body = "\n".join(lines[line_no:end_idx])

        # Check if function contains a capability predicate
        has_cap = any(re.search(pat, fn_body) for pat in CAPABILITY_PREDICATES)
        if not has_cap:
            continue

        # Check if function contains a safe handler
        has_safe = any(re.search(pat, fn_body) for pat in SAFE_HANDLERS)
        if has_safe:
            continue

        # Look for bare `return;` inside capability check without assertions in the skip block
        m = re.search(r"if\s+(!\w*|\w*\s*==\s*false)[^{]*\{([^}]*return\s*;[^}]*)\}", fn_body)
        if m:
            skip_block = m.group(2)
            if "assert!" not in skip_block and "assert_eq!" not in skip_block:
                fn_name = fn_line.strip().split("(")[0].replace("pub ", "").replace("fn ", "").strip()
                violations.append(f"{path}:{line_no + 1}: `{fn_name}` has capability-conditional early return without safe policy arming or ledger registration")
    return violations


def scan_all_test_files() -> list[str]:
    all_violations = []
    for test_file in sorted(REPO.glob("crates/*/tests/**/*.rs")):
        content = test_file.read_text(encoding="utf-8", errors="replace")
        rel_path = str(test_file.relative_to(REPO))
        violations = check_test_content(content, rel_path)
        all_violations.extend(violations)
    return all_violations


def self_test() -> int:
    ok = True

    # Bad fixture: early return without safe handler
    bad_fixture = """
    #[test]
    fn test_bad() {
        if !gpu_available() {
            return;
        }
        assert!(true);
    }
    """
    violations = check_test_content(bad_fixture, "fixture_bad.rs")
    if len(violations) != 1:
        print(f"self-test: expected 1 violation on bad fixture, got {violations}", file=sys.stderr)
        ok = False

    # Good fixture: uses arm_policy_from_env and checks gpu_required_by_policy
    good_fixture = """
    #[test]
    fn test_good() {
        support::gpu_gate::arm_policy_from_env();
        if !gpu_available() {
            if keyhog_scanner::gpu::gpu_required_by_policy() {
                panic!("GPU required");
            }
            return;
        }
        assert!(true);
    }
    """
    violations = check_test_content(good_fixture, "fixture_good.rs")
    if violations:
        print(f"self-test: expected 0 violations on good fixture, got {violations}", file=sys.stderr)
        ok = False

    print("self-test PASS" if ok else "self-test FAIL", file=sys.stderr)
    return 0 if ok else 1


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]

    if "--self-test" in argv:
        return self_test()

    violations = scan_all_test_files()
    if violations:
        print("Vacuous test gate FAIL: found unregistered capability-conditional tests:", file=sys.stderr)
        for v in violations:
            print(f"  {v}", file=sys.stderr)
        return 1

    print("Vacuous test gate: all capability-conditional tests safely arm policies or register outcomes.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
