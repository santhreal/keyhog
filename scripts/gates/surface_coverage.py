#!/usr/bin/env python3
"""Gate #4 — SURFACE COVERAGE: every subcommand has a real-process test.

The `keyhog tui` dashboard rotted unusable for two months while its UNIT tests
stayed green, because no test ever actually RAN the surface as a user would. A
feature whose only coverage is "the module compiles" is a feature-shaped shell.

This gate enumerates the real subcommand surface from the canonical `clap`
`enum Command` in `crates/cli/src/args.rs` and asserts that EVERY subcommand is
exercised by the reliability matrix in `crates/cli/tests/reliability/harness.rs`
— the suite that SPAWNS THE ACTUAL BINARY (`run(profile, &[sub, ...])`) under
16 hostile profiles and asserts clean exit / no panic / no ANSI leak / a usage
contract. A subcommand present in the binary but absent from that list = a
surface with no real-process coverage = RED BUILD.

(Interactive surfaces that need a live workflow — a TUI, a daemon stream — must
additionally carry a PTY/e2e test; there are none today after the TUI removal,
but if one is re-added, list it here as a required PTY-covered name.)

Run: python3 scripts/gates/surface_coverage.py   (exit 1 on a gap)
"""
from __future__ import annotations

import pathlib
import re
import sys

REPO = pathlib.Path(__file__).resolve().parents[2]
ARGS = REPO / "crates" / "cli" / "src" / "args.rs"
HARNESS = REPO / "crates" / "cli" / "tests" / "reliability" / "harness.rs"

# Subcommands that are interactive/long-running and are deliberately exercised
# by a DEDICATED bounded test instead of the no-arg reliability sweep, but must
# STILL appear in the harness subcommand list (for --help/--badflag coverage).
# (None require a separate allowance today; kept for clarity.)
PTY_REQUIRED: set[str] = set()


def kebab(camel: str) -> str:
    """clap's default subcommand rename: CamelCase -> kebab-case."""
    s = re.sub(r"(?<!^)(?=[A-Z])", "-", camel).lower()
    return s


def command_variants() -> set[str]:
    text = ARGS.read_text()
    m = re.search(r"enum\s+Command\s*\{(.*?)\n\}", text, re.S)
    if not m:
        print("FAIL — could not locate `enum Command` in args.rs", file=sys.stderr)
        sys.exit(2)
    body = m.group(1)
    # Strip line comments + doc comments, then grab `Variant(` / `Variant {` /
    # bare `Variant,` at the start of a (possibly attributed) line.
    names = set()
    for line in body.splitlines():
        s = line.strip()
        if s.startswith("//") or s.startswith("#["):
            continue
        vm = re.match(r"([A-Z][A-Za-z0-9]+)\s*[\({,]", s)
        if vm:
            names.add(kebab(vm.group(1)))
    return names


def covered_subcommands() -> set[str]:
    if not HARNESS.exists():
        print(f"FAIL — reliability harness not found: {HARNESS}", file=sys.stderr)
        sys.exit(2)
    text = HARNESS.read_text()
    # The SUBCOMMANDS const is the array containing "scan-system" + "daemon".
    m = re.search(r"&\[([^\]]*?\"scan-system\"[^\]]*?)\]", text, re.S)
    if not m:
        print("FAIL — could not locate the subcommand list in harness.rs", file=sys.stderr)
        sys.exit(2)
    return set(re.findall(r'"([a-z][a-z0-9-]*)"', m.group(1)))


def main() -> int:
    surface = command_variants()
    covered = covered_subcommands()
    # `help` is clap-synthesized, never a real verb.
    surface.discard("help")

    gaps = surface - covered
    stale = covered - surface  # listed as covered but no longer a real verb

    print(f"surface subcommands ({len(surface)}): {sorted(surface)}")
    print(f"covered by real-process matrix ({len(covered)}): {sorted(covered)}")

    rc = 0
    if gaps:
        print(f"\nFAIL — {len(gaps)} subcommand(s) in the binary have NO real-process "
              f"coverage: {sorted(gaps)}", file=sys.stderr)
        print("  Add each to the SUBCOMMANDS list in "
              "crates/cli/tests/reliability/harness.rs so the reliability matrix "
              "actually spawns and exercises it. An interactive surface needs a "
              "PTY/e2e test on top.", file=sys.stderr)
        rc = 1
    if stale:
        print(f"\nFAIL — {len(stale)} name(s) covered by the matrix no longer exist "
              f"as subcommands: {sorted(stale)}. Remove them from harness.rs "
              "(dead coverage hides a removed surface).", file=sys.stderr)
        rc = 1
    if rc == 0:
        print("\nOK — every subcommand surface has real-process coverage.")
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
