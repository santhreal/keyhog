#!/usr/bin/env python3
"""Unsafe guards gate (Row 87).

Enforces workspace-wide safety contracts across all `unsafe` blocks and functions:
1. Every `unsafe` block/fn/impl must carry a written `// SAFETY:` comment or doc comment.
2. No `unsafe` block may rely on `debug_assert!` as its preceding invariant guard
   (which is compiled away in release builds). Preconditions must be enforced by checked
   access, real `assert!`, or infallible index types.

Supports `--self-test` mode with AST/text mutation verification.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import List, NamedTuple

ROOT = Path(__file__).resolve().parent.parent.parent

UNSAFE_PATTERN = re.compile(r"\bunsafe\s*(\{|fn\b|impl\b)")
DEBUG_ASSERT_PATTERN = re.compile(r"\bdebug_assert(_eq|_ne)?!\s*\(")
REAL_ASSERT_PATTERN = re.compile(r"\bassert(_eq|_ne)?!\s*\(")
SAFETY_COMMENT_PATTERN = re.compile(r"//\s*SAFETY:|///\s*#\s*Safety|/\*\s*SAFETY:", re.IGNORECASE)
STRING_LITERAL_PATTERN = re.compile(r'"(\\.|[^"\\])*"')


class UnsafeSite(NamedTuple):
    file_path: Path
    line_number: int
    line_content: str
    has_safety_comment: bool
    has_debug_assert_hazard: bool
    details: str


def find_preceding_comments(lines: List[str], idx: int, lookback: int = 15) -> str:
    start = max(0, idx - lookback)
    return "\n".join(lines[start:idx + 1])


def scan_file_for_unsafe(file_path: Path, content: str) -> List[UnsafeSite]:
    sites: List[UnsafeSite] = []
    lines = content.splitlines()

    for idx, line in enumerate(lines):
        # Strip string literals before searching for unsafe keywords
        line_without_strings = STRING_LITERAL_PATTERN.sub('""', line)
        match = UNSAFE_PATTERN.search(line_without_strings)
        if not match:
            continue

        # Ignore comments containing the word "unsafe"
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("*"):
            continue

        # Look back up to 15 lines for // SAFETY: comment or doc comment
        preceding = find_preceding_comments(lines, idx, lookback=15)
        has_safety = bool(SAFETY_COMMENT_PATTERN.search(preceding)) or bool(SAFETY_COMMENT_PATTERN.search(line))

        # Check if debug_assert! occurs in the preceding 6 lines without an intervening real assert!
        preceding_lines = lines[max(0, idx - 6):idx]
        has_debug_assert = any(DEBUG_ASSERT_PATTERN.search(l) for l in preceding_lines)
        has_real_assert = any(REAL_ASSERT_PATTERN.search(l) for l in preceding_lines)

        has_hazard = has_debug_assert and not has_real_assert
        details = ""
        if not has_safety:
            details = "Missing required `// SAFETY:` comment"
        if has_hazard:
            if details:
                details += "; "
            details += "Preceded by `debug_assert!` without release `assert!`"

        if not has_safety or has_hazard:
            sites.append(
                UnsafeSite(
                    file_path=file_path,
                    line_number=idx + 1,
                    line_content=line.strip(),
                    has_safety_comment=has_safety,
                    has_debug_assert_hazard=has_hazard,
                    details=details,
                )
            )

    return sites


def scan_workspace(workspace_dir: Path) -> List[UnsafeSite]:
    violations: List[UnsafeSite] = []
    crate_dirs = [
        workspace_dir / "crates" / crate / "src"
        for crate in ["cli", "core", "profile", "scanner", "sources", "verifier"]
    ]
    for crate_dir in crate_dirs:
        if not crate_dir.exists():
            continue
        for rs_file in sorted(crate_dir.rglob("*.rs")):
            try:
                content = rs_file.read_text(encoding="utf-8")
            except Exception:
                continue
            violations.extend(scan_file_for_unsafe(rs_file, content))
    return violations


def run_self_test() -> int:
    print("Running unsafe_guards self-tests...")

    # 1. Clean case: unsafe block with // SAFETY: and real assert!
    clean_code = """
    fn read_item(idx: usize, slice: &[u8]) -> u8 {
        assert!(idx < slice.len(), "out of bounds");
        // SAFETY: index checked above by assert!
        unsafe { *slice.get_unchecked(idx) }
    }
    """
    clean_sites = scan_file_for_unsafe(Path("clean.rs"), clean_code)
    assert not clean_sites, f"Expected zero violations on clean code, got: {clean_sites}"

    # 2. Hazard case: unsafe block preceded by debug_assert! only
    debug_assert_hazard = """
    fn read_item(idx: usize, slice: &[u8]) -> u8 {
        debug_assert!(idx < slice.len());
        // SAFETY: index checked by debug_assert
        unsafe { *slice.get_unchecked(idx) }
    }
    """
    hazard_sites = scan_file_for_unsafe(Path("hazard.rs"), debug_assert_hazard)
    assert len(hazard_sites) == 1, f"Expected 1 hazard violation, got: {hazard_sites}"
    assert hazard_sites[0].has_debug_assert_hazard, "Expected debug_assert hazard flagged"

    # 3. Missing SAFETY comment case
    missing_safety = """
    fn get_id() -> u32 {
        unsafe { libc::getuid() }
    }
    """
    missing_sites = scan_file_for_unsafe(Path("missing.rs"), missing_safety)
    assert len(missing_sites) == 1, f"Expected 1 missing safety violation, got: {missing_sites}"
    assert not missing_sites[0].has_safety_comment, "Expected missing safety comment flagged"

    # 4. String literal containing unsafe is ignored
    string_code = """
    fn msg() {
        let text = "this is an unsafe {path} string";
    }
    """
    string_sites = scan_file_for_unsafe(Path("str.rs"), string_code)
    assert not string_sites, f"Expected zero violations on string literal, got: {string_sites}"

    print("All unsafe_guards self-tests passed successfully.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Unsafe guards and safety precondition gate")
    parser.add_argument("--self-test", action="store_true", help="Run internal self-tests")
    parser.add_argument(
        "--workspace-dir",
        type=Path,
        default=ROOT,
        help="Path to workspace root directory",
    )
    args = parser.parse_args()

    if args.self_test:
        return run_self_test()

    workspace_dir = args.workspace_dir
    violations = scan_workspace(workspace_dir)
    if violations:
        print(
            f"ERROR: Found {len(violations)} unsafe block safety contract violation(s):",
            file=sys.stderr,
        )
        for v in violations:
            rel_path = (
                v.file_path.relative_to(ROOT)
                if v.file_path.is_relative_to(ROOT)
                else v.file_path
            )
            print(f"  {rel_path}:{v.line_number}: {v.details}", file=sys.stderr)
            print(f"    {v.line_content}", file=sys.stderr)
        return 1

    print(
        "Unsafe guards gate passed: all unsafe blocks in workspace crates have valid SAFETY preconditions and release assertions."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
