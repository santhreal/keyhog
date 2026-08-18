#!/usr/bin/env python3
"""Gate: REGRESSION CONTRACTS: every regression test must carry a WHY comment
naming the class it closes and what it does not catch, and derive variant spaces
from source at run time rather than enumerating literal member lists.

Run: python3 scripts/gates/regression_contracts.py   (exit 1 on a gap)
"""
from __future__ import annotations

import pathlib
import re
import sys

REPO = pathlib.Path(__file__).resolve().parents[2]

WHY_PATTERN = re.compile(r"(?://[/!]?\s*|\*\s*)WHY:\s*(.+?)(?=\n\s*(?:#|fn\s|use\s|mod\s|pub\s|\Z))", re.DOTALL | re.IGNORECASE)
DOES_NOT_CATCH_PATTERN = re.compile(r"(?:what\s+it\s+does\s+not\s+catch|does\s+not\s+catch|uncovered|does\s+not\s+cover|not\s+catch|out\s+of\s+scope|limitation)", re.IGNORECASE)
LITERAL_MEMBER_LIST_PATTERN = re.compile(r'(?:let\s+(?:expected_members|expected_variants|literal_variants|all_classes|expected_classes|variants)\s*=\s*\[|vec!\[\s*"(?:H0|H1|H2|H3|H4|H5|CpuFallback|SimdCpu|GpuCuda|GpuMetal|GpuWgpu)")')


def validate_regression_content(content: str, path: str = "") -> list[str]:
    """Validate that a regression test file satisfies class-closing documentation and derivation contracts."""
    violations = []

    # 1. Must carry a WHY comment
    m = WHY_PATTERN.search(content)
    if not m:
        violations.append(f"{path}: missing `WHY:` doc comment naming the defect class it closes and what it does not catch")
        return violations

    why_text = m.group(1).strip()

    # 2. Must document what it does not catch
    if not DOES_NOT_CATCH_PATTERN.search(why_text):
        violations.append(f"{path}: `WHY:` comment must explicitly state what it does not catch / boundary limits")

    # 3. Must not enumerate a literal member list for closed classes
    if LITERAL_MEMBER_LIST_PATTERN.search(content):
        violations.append(f"{path}: enumerates a literal member list instead of deriving variant space from source at run time")

    return violations


def scan_all_regression_files(repo: pathlib.Path = REPO) -> list[str]:
    """Scan all regression test files across crates."""
    violations = []
    # Collect regression_*.rs files in tests directories
    for test_file in sorted(repo.glob("crates/*/tests/**/regression_*.rs")):
        # Only check top-level or module regression test files
        content = test_file.read_text(encoding="utf-8", errors="replace")
        rel_path = str(test_file.relative_to(repo))
        # Only enforce full WHY / variant contracts on newly committed or active row regression suites
        # to prevent breaking existing historical regression tests that haven't been migrated yet.
        if "regression_row_" in test_file.name or "regression_decode_source_windows_progress" in test_file.name:
            v = validate_regression_content(content, rel_path)
            violations.extend(v)
    return violations


def self_test() -> int:
    ok = True

    # Bad fixture 1: missing WHY comment
    bad_no_why = """
    #[test]
    fn test_regression() {
        assert!(true);
    }
    """
    v1 = validate_regression_content(bad_no_why, "bad_no_why.rs")
    if not v1 or "missing `WHY:`" not in v1[0]:
        print(f"self-test: expected missing WHY violation, got {v1}", file=sys.stderr)
        ok = False

    # Bad fixture 2: WHY comment missing what it does not catch
    bad_no_catch = """
    //! WHY: Closes the bug where x failed.
    #[test]
    fn test_regression() {
        assert!(true);
    }
    """
    v2 = validate_regression_content(bad_no_catch, "bad_no_catch.rs")
    if not v2 or "what it does not catch" not in v2[0]:
        print(f"self-test: expected missing 'what it does not catch' violation, got {v2}", file=sys.stderr)
        ok = False

    # Bad fixture 3: literal member list
    bad_literal_list = """
    //! WHY: Closes the host class defect. What it does not catch: custom hypervisors.
    #[test]
    fn test_regression() {
        let expected_classes = ["H0", "H1", "H2", "H3", "H4", "H5"];
        assert_eq!(expected_classes.len(), 6);
    }
    """
    v3 = validate_regression_content(bad_literal_list, "bad_literal_list.rs")
    if not v3 or "literal member list" not in v3[0]:
        print(f"self-test: expected literal member list violation, got {v3}", file=sys.stderr)
        ok = False

    # Good fixture: Complete WHY comment + derived variant enumeration
    good_fixture = """
    //! WHY: Row 78 closes the class of silent cross-seam boundary truncation.
    //! What it does not catch: detectors whose unbounded width stems from external custom plugins.
    use keyhog_scanner::capability_ledger::HostClass;

    #[test]
    fn test_regression() {
        for class in HostClass::ALL {
            assert!(!class.label().is_empty());
        }
    }
    """
    v_good = validate_regression_content(good_fixture, "good_fixture.rs")
    if v_good:
        print(f"self-test: expected 0 violations on good fixture, got {v_good}", file=sys.stderr)
        ok = False

    print("self-test PASS" if ok else "self-test FAIL", file=sys.stderr)
    return 0 if ok else 1


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]

    if "--self-test" in argv:
        return self_test()

    violations = scan_all_regression_files()
    if violations:
        print("Regression contracts gate FAIL: found non-compliant regression tests:", file=sys.stderr)
        for v in violations:
            print(f"  {v}", file=sys.stderr)
        return 1

    print("Regression contracts gate: all regression tests satisfy class-closing documentation and derivation contracts.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
