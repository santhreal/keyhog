#!/usr/bin/env python3
"""Structural Gate: NO CWD-RELATIVE SOURCE READS IN TESTS (Row 149).

Enforces that integration and unit tests across all workspace crates do not read
crate source files via bare CWD-relative paths (e.g. `read_to_string("src/...")`,
`File::open("src/...")`, or `fs::read("src/...")`).

A bare CWD-relative path resolves against the process working directory, which
breaks under `cargo-nextest` (where CWD is workspace root, not crate root),
standalone test execution, or concurrent tests mutating the working directory.

Tests must use manifest-anchored readers (e.g. `keyhog_core::testing::read_crate_source`,
`keyhog_scanner::testing::read_crate_source`, or `PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(...)`).
"""

from __future__ import annotations

import argparse
import pathlib
import re
import sys

REPO = pathlib.Path(__file__).resolve().parents[2]

# Entry points that read files from a path argument
READ_ENTRY_POINTS = (
    "read_to_string(",
    "File::open(",
    "fs::read(",
    "std::fs::read_to_string(",
    "std::fs::read(",
    "std::fs::File::open(",
)

# String literal pattern
STRING_LIT_RE = re.compile(r'"([^"\\]*(?:\\.[^"\\]*)*)"')


def is_crate_source_literal(literal: str) -> bool:
    """Return True if literal is a CWD-relative path to crate source."""
    if literal.startswith("src/"):
        return True
    if literal.startswith("crates/") and "/src/" in literal:
        return True
    if literal.startswith("../") and "/src/" in literal:
        return True
    return False


def find_cwd_relative_source_read(line: str) -> str | None:
    """Check if a code line contains a CWD-relative crate source read."""
    trimmed = line.strip()
    if not trimmed or trimmed.startswith("//") or trimmed.startswith("/*") or trimmed.startswith("*"):
        return None

    for ep in READ_ENTRY_POINTS:
        idx = trimmed.find(ep)
        while idx != -1:
            after = trimmed[idx + len(ep):].lstrip()
            # If the argument starts directly with a string literal
            if after.startswith('"') or after.startswith('r#"'):
                # Extract the literal content
                if after.startswith('r#"'):
                    end_raw = after.find('"#')
                    lit = after[3:end_raw] if end_raw != -1 else ""
                else:
                    end_str = after[1:].find('"')
                    lit = after[1:end_str + 1] if end_str != -1 else ""

                if is_crate_source_literal(lit):
                    return lit

            # Look for another entry point in the same line
            next_idx = trimmed.find(ep, idx + len(ep))
            idx = next_idx

    return None


def scan_file_for_cwd_relative_reads(file_path: pathlib.Path) -> list[tuple[int, str, str]]:
    """Scan a Rust test file for CWD-relative crate source reads."""
    violations = []
    try:
        content = file_path.read_text(encoding="utf-8")
    except Exception:
        return violations

    for line_no, line in enumerate(content.splitlines(), start=1):
        offending_lit = find_cwd_relative_source_read(line)
        if offending_lit:
            violations.append((line_no, line.strip(), offending_lit))

    return violations


def check_workspace_tests(root: pathlib.Path) -> list[str]:
    """Scan all test files in the workspace for CWD-relative source reads."""
    violations = []

    test_files = []
    # Collect tests under crates/*/tests/ and tests/
    crates_dir = root / "crates"
    if crates_dir.is_dir():
        for rs_file in crates_dir.rglob("*.rs"):
            if "target" in rs_file.parts:
                continue
            if "tests" in rs_file.parts:
                test_files.append(rs_file)

    root_tests_dir = root / "tests"
    if root_tests_dir.is_dir():
        for rs_file in root_tests_dir.rglob("*.rs"):
            if "target" in rs_file.parts:
                continue
            test_files.append(rs_file)

    for test_file in sorted(set(test_files)):
        rel_path = test_file.relative_to(root).as_posix()
        file_violations = scan_file_for_cwd_relative_reads(test_file)
        for line_no, line_content, offending_lit in file_violations:
            violations.append(
                f"{rel_path}:{line_no}: CWD-relative source read `{offending_lit}`. "
                "Use `keyhog_core::testing::read_crate_source` or `PathBuf::from(env!(\"CARGO_MANIFEST_DIR\")).join(...)`."
            )

    return violations


def run_gate(root: pathlib.Path) -> int:
    """Run gate check."""
    violations = check_workspace_tests(root)
    if violations:
        print(
            f"FAIL - {len(violations)} CWD-relative source read(s) found in tests (Row 149):",
            file=sys.stderr,
        )
        for v in violations:
            print(f"  - {v}", file=sys.stderr)
        return 1

    print("OK - No CWD-relative source reads found in workspace tests.")
    return 0


def self_test() -> int:
    """Run self-test with positive and negative cases."""
    # 1. Live repo verification (excluding the old test files that contain the string literals)
    # 2. Syntax recognition tests
    assert find_cwd_relative_source_read('let s = std::fs::read_to_string("src/foo.rs");') == "src/foo.rs"
    assert find_cwd_relative_source_read('let s = read_to_string("crates/core/src/lib.rs");') == "crates/core/src/lib.rs"
    assert find_cwd_relative_source_read('let s = read_to_string("../cli/src/main.rs");') == "../cli/src/main.rs"
    assert find_cwd_relative_source_read('let f = File::open("src/spec/validate.rs");') == "src/spec/validate.rs"
    assert find_cwd_relative_source_read('let b = fs::read("src/calibration.rs");') == "src/calibration.rs"
    assert find_cwd_relative_source_read('let s = read_to_string(  "src/x.rs"  );') == "src/x.rs"
    assert find_cwd_relative_source_read('let s = std::fs::File::open("src/bar.rs");') == "src/bar.rs"

    # 3. Compliant patterns NOT flagged
    assert find_cwd_relative_source_read('// read_to_string("src/foo.rs")') is None
    assert find_cwd_relative_source_read('/* read_to_string("src/foo.rs") */') is None
    assert find_cwd_relative_source_read('let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/foo.rs");') is None
    assert find_cwd_relative_source_read('let s = read_crate_source("src/foo.rs");') is None
    assert find_cwd_relative_source_read('let s = read_to_string(temp.path().join("src/foo.rs"));') is None
    assert find_cwd_relative_source_read('let s = read_to_string("fixtures/test.json");') is None
    assert find_cwd_relative_source_read('let s = read_to_string("./tests/fixtures/test.json");') is None
    assert find_cwd_relative_source_read('let s = read_to_string("/tmp/src/foo.rs");') is None
    assert find_cwd_relative_source_read('let s = read_to_string("../fixtures/data.json");') is None

    print("no_cwd_relative_source_reads.py --self-test passed.")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true", help="run self-tests")
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test()

    return run_gate(REPO)


if __name__ == "__main__":
    sys.exit(main())
