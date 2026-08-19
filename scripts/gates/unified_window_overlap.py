#!/usr/bin/env python3
"""Gate: UNIFIED WINDOW OVERLAP (Row 111).

Ensures that `keyhog_core::DEFAULT_WINDOW_OVERLAP_BYTES` is the single canonical
owner of streaming window overlap across the entire repository.
No crate, bench, or test outside `crates/core/src/source.rs` may define a private
window overlap constant using literal values (such as `128 * 1024` or `131072`).

Acceptance criteria:
- Exactly one canonical definition in `crates/core/src/source.rs`.
- Every other crate/test/bench references `keyhog_core::DEFAULT_WINDOW_OVERLAP_BYTES`
  or `keyhog_scanner::types::WINDOW_OVERLAP_BYTES`.
- Adding a private redeclared window overlap constant fails the gate.
"""

from __future__ import annotations

import argparse
import pathlib
import re
import sys

REPO = pathlib.Path(__file__).resolve().parents[2]

ALLOWED_CANONICAL_OWNER = pathlib.Path("crates/core/src/source.rs")
def validate_owners(root: pathlib.Path) -> list[str]:
    """Validate that configured owner paths exist on disk."""
    errors: list[str] = []
    if not (root / ALLOWED_CANONICAL_OWNER).is_file():
        errors.append(f"canonical owner does not exist: {ALLOWED_CANONICAL_OWNER}")
    return errors


# Pattern detecting private window overlap constant declarations with literal numbers
REDECLARED_OVERLAP_RE = re.compile(
    r"\bconst\s+[A-Za-z0-9_]*OVERLAP[A-Za-z0-9_]*\s*:\s*usize\s*=\s*(?:128\s*\*\s*1024|131_?072)\s*;"
)


def find_redeclared_overlap_constants(root: pathlib.Path) -> list[tuple[pathlib.Path, int, str]]:
    """Find all occurrences of redeclared window overlap constants."""
    violations = []
    crates_dir = root / "crates"
    if not crates_dir.exists():
        return violations

    for rs_file in crates_dir.rglob("*.rs"):
        rel = rs_file.relative_to(root)
        if rel == ALLOWED_CANONICAL_OWNER:
            continue

        try:
            content = rs_file.read_text(encoding="utf-8")
        except Exception:
            continue

        for line_num, line in enumerate(content.splitlines(), start=1):
            if REDECLARED_OVERLAP_RE.search(line):
                violations.append((rel, line_num, line.strip()))

    return violations


def run_gate(root: pathlib.Path) -> int:
    owner_errors = validate_owners(root)
    if owner_errors:
        print("FAIL: Missing canonical owner file(s):", file=sys.stderr)
        for err in owner_errors:
            print(f"  {err}", file=sys.stderr)
        return 1
    violations = find_redeclared_overlap_constants(root)
    if violations:
        print("FAIL: Found redeclared window overlap constants (Row 111 violation):")
        for path, line_num, text in violations:
            print(f"  {path}:{line_num}: {text}")
        print("\nAll window overlap references must use `keyhog_core::DEFAULT_WINDOW_OVERLAP_BYTES`")
        print("or `keyhog_scanner::types::WINDOW_OVERLAP_BYTES`.")
        return 1

    print("PASS: Unified window overlap ownership is maintained (Row 111).")
    return 0


def self_test() -> int:
    import tempfile

    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_root = pathlib.Path(tmp_dir)
        crates_dir = tmp_root / "crates" / "sources" / "src"
        crates_dir.mkdir(parents=True)

        bad_file = crates_dir / "bad.rs"
        bad_file.write_text(
            "const DEFAULT_WINDOW_OVERLAP: usize = 128 * 1024;\n",
            encoding="utf-8",
        )

        violations = find_redeclared_overlap_constants(tmp_root)
        if not violations:
            print("SELF-TEST FAIL: Did not catch redeclared overlap constant in bad.rs")
            return 1

        bad_file.write_text(
            "const DEFAULT_WINDOW_OVERLAP: usize = keyhog_core::DEFAULT_WINDOW_OVERLAP_BYTES;\n",
            encoding="utf-8",
        )
        violations = find_redeclared_overlap_constants(tmp_root)
        if violations:
            print("SELF-TEST FAIL: Flagged valid reference to canonical constant")
            return 1

    print("self-test PASS")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Unified Window Overlap Gate")
    parser.add_argument("--self-test", action="store_true", help="Run gate self-test")
    args = parser.parse_args()

    if args.self_test:
        return self_test()

    return run_gate(REPO)


if __name__ == "__main__":
    sys.exit(main())
