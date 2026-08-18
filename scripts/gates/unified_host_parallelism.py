#!/usr/bin/env python3
"""Gate: UNIFIED HOST PARALLELISM (Row 110).

Ensures that `keyhog_profile::host_parallelism` is the single canonical owner
of host width and parallelism resolution across the entire repository.
No crate outside `crates/profile/src/host_parallelism.rs` may call
`std::thread::available_parallelism()`.

Acceptance criteria:
- Exactly one site calls `available_parallelism` in `crates/profile/src/host_parallelism.rs`.
- Every other crate/test/bench queries `keyhog_profile::logical_cpus()` / `host_parallelism()`.
- Adding a direct call to `available_parallelism` outside the owner fails the suite.
"""

from __future__ import annotations

import argparse
import pathlib
import re
import sys

REPO = pathlib.Path(__file__).resolve().parents[2]

ALLOWED_OWNER = pathlib.Path("crates/profile/src/host_parallelism.rs")
PARALLELISM_CALL_RE = re.compile(r"available_parallelism\s*\(")


def find_parallelism_calls(root: pathlib.Path) -> list[tuple[pathlib.Path, int, str]]:
    """Find all occurrences of available_parallelism() in source files."""
    violations = []
    crates_dir = root / "crates"
    if not crates_dir.exists():
        return violations

    for rs_file in crates_dir.rglob("*.rs"):
        rel = rs_file.relative_to(root)
        if rel == ALLOWED_OWNER:
            continue
        try:
            content = rs_file.read_text(encoding="utf-8")
        except Exception:
            continue

        for line_num, line in enumerate(content.splitlines(), start=1):
            # Ignore line comments
            stripped = line.strip()
            if stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("*"):
                continue
            if PARALLELISM_CALL_RE.search(line):
                violations.append((rel, line_num, line.strip()))

    return violations


def run_gate(root: pathlib.Path) -> int:
    violations = find_parallelism_calls(root)
    if violations:
        print("FAIL: Stray available_parallelism() calls found outside canonical owner:")
        for path, line_num, text in violations:
            print(f"  {path}:{line_num} -> {text}")
        print(f"\nHost parallelism must resolve through {ALLOWED_OWNER} only (Row 110).")
        return 1

    print("Gate passed: Unified Host Parallelism Ownership (Row 110)")
    return 0


def self_test() -> int:
    import tempfile

    with tempfile.TemporaryDirectory() as tmpdir:
        root = pathlib.Path(tmpdir)
        crates = root / "crates" / "scanner" / "src"
        crates.mkdir(parents=True)
        bad_file = crates / "sample.rs"
        bad_file.write_text("let _n = std::thread::available_parallelism();\n", encoding="utf-8")

        res = find_parallelism_calls(root)
        assert len(res) == 1, f"Expected 1 violation in self-test, got {len(res)}"

        bad_file.write_text("let _n = keyhog_profile::logical_cpus();\n", encoding="utf-8")
        res2 = find_parallelism_calls(root)
        assert len(res2) == 0, f"Expected 0 violations after fix, got {len(res2)}"

    print("unified_host_parallelism.py --self-test passed.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Unified Host Parallelism Gate")
    parser.add_argument("--self-test", action="store_true", help="Run self-tests")
    args = parser.parse_args()

    if args.self_test:
        return self_test()

    return run_gate(REPO)


if __name__ == "__main__":
    sys.exit(main())
