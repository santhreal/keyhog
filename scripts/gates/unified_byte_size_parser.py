#!/usr/bin/env python3
"""Gate: UNIFIED BYTE SIZE PARSER (Row 112).

Ensures that `keyhog::value_parsers::parse_byte_size` is the single canonical
owner of human-readable byte size parsing across the entire repository.
No crate, subcommand, or module outside `crates/cli/src/value_parsers.rs` may
define a private `fn parse_byte_size`.

Acceptance criteria:
- Exactly one canonical `parse_byte_size` definition in `crates/cli/src/value_parsers.rs`.
- Every other subcommand, daemon, config loader, and test references the canonical parser.
- Adding a private redeclared `fn parse_byte_size` fails the gate.
"""

from __future__ import annotations

import argparse
import pathlib
import re
import sys

REPO = pathlib.Path(__file__).resolve().parents[2]

ALLOWED_CANONICAL_OWNER = pathlib.Path("crates/cli/src/value_parsers.rs")
ALLOWED_TESTING_TRAIT = pathlib.Path("crates/cli/src/testing.rs")

# Pattern detecting private fn parse_byte_size definitions
PRIVATE_PARSE_BYTE_SIZE_RE = re.compile(
    r"\bfn\s+parse_byte_size\s*\("
)

def validate_owners(root: pathlib.Path) -> list[str]:
    """Validate that configured owner paths exist on disk."""
    errors: list[str] = []
    if not (root / ALLOWED_CANONICAL_OWNER).is_file():
        errors.append(f"canonical owner does not exist: {ALLOWED_CANONICAL_OWNER}")
    if not (root / ALLOWED_TESTING_TRAIT).is_file():
        errors.append(f"testing trait owner does not exist: {ALLOWED_TESTING_TRAIT}")
    return errors


def find_private_byte_size_parsers(root: pathlib.Path) -> list[tuple[pathlib.Path, int, str]]:
    violations = []
    crates_dir = root / "crates"
    if not crates_dir.exists():
        return violations

    for rs_file in crates_dir.rglob("*.rs"):
        rel = rs_file.relative_to(root)
        if rel == ALLOWED_CANONICAL_OWNER or rel == ALLOWED_TESTING_TRAIT:
            continue

        try:
            content = rs_file.read_text(encoding="utf-8")
        except Exception:
            continue

        for line_num, line in enumerate(content.splitlines(), start=1):
            if PRIVATE_PARSE_BYTE_SIZE_RE.search(line):
                violations.append((rel, line_num, line.strip()))

    return violations


def run_gate(root: pathlib.Path) -> int:
    owner_errors = validate_owners(root)
    if owner_errors:
        print("FAIL: Missing canonical owner file(s):", file=sys.stderr)
        for err in owner_errors:
            print(f"  {err}", file=sys.stderr)
        return 1
    violations = find_private_byte_size_parsers(root)
    if violations:
        print("FAIL: Found private byte size parser functions (Row 112 violation):")
        for path, line_num, text in violations:
            print(f"  {path}:{line_num}: {text}")
        print("\nAll byte size parsing must use `keyhog::value_parsers::parse_byte_size`.")
        return 1
    print("PASS: Unified byte size parser ownership is maintained (Row 112).")
    return 0


def self_test() -> int:
    import tempfile

    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_root = pathlib.Path(tmp_dir)
        crates_dir = tmp_root / "crates" / "cli" / "src" / "subcommands"
        crates_dir.mkdir(parents=True)

        bad_file = crates_dir / "bad_daemon.rs"
        bad_file.write_text(
            "fn parse_byte_size(s: &str) -> Option<usize> { None }\n",
            encoding="utf-8",
        )

        violations = find_private_byte_size_parsers(tmp_root)
        if not violations:
            print("SELF-TEST FAIL: Did not catch private parse_byte_size in bad_daemon.rs")
            return 1

        bad_file.write_text(
            "let size = crate::value_parsers::parse_byte_size(s);\n",
            encoding="utf-8",
        )
        violations = find_private_byte_size_parsers(tmp_root)
        if violations:
            print("SELF-TEST FAIL: Flagged valid call to canonical parser")
            return 1

    print("self-test PASS")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Unified Byte Size Parser Gate")
    parser.add_argument("--self-test", action="store_true", help="Run gate self-test")
    args = parser.parse_args()

    if args.self_test:
        return self_test()

    return run_gate(REPO)


if __name__ == "__main__":
    sys.exit(main())
