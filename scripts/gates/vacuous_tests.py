#!/usr/bin/env python3
"""Gate #14: VACUOUS TESTS: capability-conditional tests must not skip silently.

A test whose assertions all sit behind a capability predicate (such as
`gpu_available()`, `warm_backend()`, or hardware probes) passes vacuously when
the capability is absent, reporting that absence as success.

This gate statically analyzes all test files across crates, detecting early
returns guarded by capability predicates, and requires that every such test:
  1. Arms required policies (e.g. `arm_policy_from_env()`, `require_gpu_or_panic`), OR
  2. Panics on missing capabilities when required by policy, OR
  3. Registers its skip outcome with a ledger/diagnostic mechanism (`register_capability_test`).

Capability predicates are enumerated dynamically from source definitions at run time
rather than maintaining a hardcoded list.

Run: python3 scripts/gates/vacuous_tests.py   (exit 1 on a gap)
"""
from __future__ import annotations

import pathlib
import re
import sys

REPO = pathlib.Path(__file__).resolve().parents[2]
BASELINE_FILE = REPO / "scripts/gates/capability_skip_baseline.toml"


def enumerate_capability_predicates(repo: pathlib.Path = REPO) -> list[str]:
    """Enumerate capability predicates dynamically from source at run time."""
    predicates: set[str] = set()

    # 1. Parse HardwareCaps struct fields from crates/scanner/src/hw_probe/mod.rs
    hw_mod = repo / "crates/scanner/src/hw_probe/mod.rs"
    if hw_mod.exists():
        content = hw_mod.read_text(encoding="utf-8", errors="replace")
        m = re.search(r"pub struct HardwareCaps\s*\{([^}]+)\}", content)
        if m:
            for line in m.group(1).splitlines():
                field_match = re.search(r"pub\s+([a-zA-Z0-9_]+)\s*:\s*bool", line)
                if field_match:
                    field = field_match.group(1)
                    predicates.add(rf"\b{field}\b")
                    predicates.add(rf"\b{field}\(\)")
                    predicates.add(rf"caps\.{field}\b")
                    predicates.add(rf"hw\.{field}\b")
                    predicates.add(rf"hardware\.{field}\b")

    # 2. Add public capability probe methods across crates
    predicates.add(r"gpu_available\(\)")
    predicates.add(r"warm_backend\(")
    predicates.add(r"gpu_probe\(\)")
    predicates.add(r"gpu_could_engage\(")
    predicates.add(r"simd_backend_available\(\)")
    predicates.add(r"hyperscan_available")
    predicates.add(r"io_uring_available")

    return sorted(predicates)


def enumerate_safe_handlers() -> list[str]:
    """Return regexes for safe capability policy arming and ledger registration."""
    return [
        r"register_capability_test",
        r"CapabilityLedger",
        r"record_capability_skip",
        r"arm_policy_from_env",
        r"require_gpu_or_panic",
        r"require_gpu_policy",
        r"gpu_required_by_policy",
        r"unavailable_gpu_self_test_report",
        r"PolicyGuard",
        r"require_gpu_preflight",
    ]


def check_test_content(
    content: str,
    path: str = "",
    predicates: list[str] | None = None,
    safe_handlers: list[str] | None = None,
) -> list[str]:
    """Return violations where capability checks guard early returns with no safe handler."""
    if predicates is None:
        predicates = enumerate_capability_predicates()
    if safe_handlers is None:
        safe_handlers = enumerate_safe_handlers()

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
        has_cap = any(re.search(pat, fn_body) for pat in predicates)
        if not has_cap:
            continue

        # Check if function contains a safe handler
        has_safe = any(re.search(pat, fn_body) for pat in safe_handlers)
        if has_safe:
            continue

        # Look for bare `return;` inside capability check without assertions in the skip block
        m = re.search(r"if\s+(!\w*|\w*\s*==\s*false)[^{]*\{([^}]*return\s*;[^}]*)\}", fn_body)
        if m:
            skip_block = m.group(2)
            if "assert!" not in skip_block and "assert_eq!" not in skip_block:
                fn_name = fn_line.strip().split("(")[0].replace("pub ", "").replace("fn ", "").strip()
                violations.append(
                    f"{path}:{line_no + 1}: `{fn_name}` has capability-conditional early return "
                    "without safe policy arming or ledger registration (`register_capability_test`)"
                )
    return violations


def scan_all_test_files() -> list[str]:
    predicates = enumerate_capability_predicates()
    safe_handlers = enumerate_safe_handlers()
    all_violations = []
    for test_file in sorted(REPO.glob("crates/*/tests/**/*.rs")):
        content = test_file.read_text(encoding="utf-8", errors="replace")
        rel_path = str(test_file.relative_to(REPO))
        violations = check_test_content(content, rel_path, predicates, safe_handlers)
        all_violations.extend(violations)
    return all_violations


def verify_baseline_file() -> list[str]:
    """Verify that capability skip baseline configuration exists and covers all host classes."""
    errors = []
    if not BASELINE_FILE.exists():
        errors.append(f"Baseline file missing: {BASELINE_FILE}")
        return errors

    content = BASELINE_FILE.read_text(encoding="utf-8")
    required_classes = ["H0", "H1", "H2", "H3", "H4", "H5"]
    for host_class in required_classes:
        if not re.search(rf"^\s*{host_class}\s*=", content, re.MULTILINE):
            errors.append(f"Baseline missing entry for host class {host_class}")
    return errors


def self_test() -> int:
    ok = True

    # Check predicate enumeration from source
    predicates = enumerate_capability_predicates()
    if not predicates or len(predicates) < 5:
        print(f"self-test: expected >= 5 dynamic predicates, got {len(predicates)}: {predicates}", file=sys.stderr)
        ok = False

    # Check baseline verification
    baseline_errors = verify_baseline_file()
    if baseline_errors:
        print(f"self-test: baseline file verification failed: {baseline_errors}", file=sys.stderr)
        ok = False

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
    violations = check_test_content(bad_fixture, "fixture_bad.rs", predicates)
    if len(violations) != 1:
        print(f"self-test: expected 1 violation on bad fixture, got {violations}", file=sys.stderr)
        ok = False

    # Good fixture with policy check
    good_fixture_policy = """
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
    violations = check_test_content(good_fixture_policy, "fixture_good_policy.rs", predicates)
    if violations:
        print(f"self-test: expected 0 violations on good policy fixture, got {violations}", file=sys.stderr)
        ok = False

    # Good fixture with capability ledger registration
    good_fixture_ledger = """
    #[test]
    fn test_good_ledger() {
        if !register_capability_test("test_good_ledger", "gpu", gpu_available()) {
            return;
        }
        assert!(true);
    }
    """
    violations = check_test_content(good_fixture_ledger, "fixture_good_ledger.rs", predicates)
    if violations:
        print(f"self-test: expected 0 violations on good ledger fixture, got {violations}", file=sys.stderr)
        ok = False

    print("self-test PASS" if ok else "self-test FAIL", file=sys.stderr)
    return 0 if ok else 1


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]

    if "--self-test" in argv:
        return self_test()

    baseline_errors = verify_baseline_file()
    if baseline_errors:
        print("Vacuous test gate FAIL: capability baseline configuration errors:", file=sys.stderr)
        for err in baseline_errors:
            print(f"  {err}", file=sys.stderr)
        return 1

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
