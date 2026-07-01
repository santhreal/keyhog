#!/usr/bin/env python3
"""Fail if any standalone verifier test file is a CI-orphan.

CI runs the verifier suite through ONE aggregator step,
`cargo test -p keyhog-verifier --test all_tests` (plus any explicit `--test
<name>` steps in the workflows). A top-level `crates/verifier/tests/*.rs` file
compiles as its OWN separate integration-test target; unless it is also
`#[path]`-included into the `all_tests` module tree (directly in `all_tests.rs`
or transitively via a directory `mod.rs`), the `--test all_tests` step never
invokes it. Its `#[test]`s then never run in CI and the regression it guards can
ship silently.

This gate existed nowhere before: 14 top-level files were orphaned at once —
including the AWS SigV4 byte-exact known-answer locks (a signature wrong by one
byte flips a live AWS key to a false `Dead` verdict) and the SSRF short-form-IP
blocklist. This is the verifier analogue of `recall_locks_wired.py`, but it
covers EVERY top-level `tests/*.rs` (not only `regression_*`) and treats a file
as wired whether it is `#[path]`-included as a sibling (`"name.rs"`) or from a
subdirectory (`"../name.rs"`).

A file `crates/verifier/tests/<stem>.rs` is wired iff its stem is either:
  * captured by a `#[path = "…/<stem>.rs"]` include in ANY `.rs` under the
    verifier tests tree, or
  * named by a `--test <stem>` flag in any .github/workflows/*.yml step.
`all_tests.rs` itself is the aggregator root (run directly) and is excluded.
"""

from __future__ import annotations

import pathlib
import re
import subprocess
import sys

REPO = pathlib.Path(__file__).resolve().parents[2]
TESTS_REL = "crates/verifier/tests"
TESTS_DIR = REPO / TESTS_REL
WORKFLOWS = REPO / ".github/workflows"

# The aggregator root: run directly by `--test all_tests`, never a module.
AGGREGATOR = "all_tests"

# Files intentionally NOT aggregated (run in CI by some other explicit means).
# Keep tiny and justified; an entry here is a promise the file runs in CI.
ALLOWED: set[str] = set()

# Capture the stem from any `#[path = "…/<stem>.rs"]`, sibling or `../`-prefixed.
PATH_INCLUDE = re.compile(r'#\[path\s*=\s*"(?:[^"]*/)?([A-Za-z0-9_]+)\.rs"\]')
TEST_FLAG = re.compile(r"--test\s+([A-Za-z0-9_]+)")


def wired_stems() -> set[str]:
    stems: set[str] = set()
    if TESTS_DIR.is_dir():
        for rs in TESTS_DIR.rglob("*.rs"):
            stems |= set(PATH_INCLUDE.findall(rs.read_text()))
    if WORKFLOWS.is_dir():
        for wf in sorted(WORKFLOWS.glob("*.yml")):
            stems |= set(TEST_FLAG.findall(wf.read_text()))
    return stems


def top_level_test_files() -> list[str]:
    """Git-tracked top-level `tests/*.rs` stems (excluding the aggregator root).

    Tracks the committed tree (matching CI's clean checkout) so an untracked
    scratch test cannot trip the gate.
    """
    try:
        listing = subprocess.run(
            ["git", "-C", str(REPO), "ls-files", "-z", f"{TESTS_REL}/*.rs"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout
        rels = [r for r in listing.split("\0") if r]
    except (OSError, subprocess.CalledProcessError):
        rels = [p.relative_to(REPO).as_posix() for p in TESTS_DIR.glob("*.rs")]
    depth = TESTS_REL.count("/") + 1
    return sorted(
        stem
        for r in rels
        if r.count("/") == depth and r.endswith(".rs")
        for stem in [r.rsplit("/", 1)[-1][: -len(".rs")]]
        if stem != AGGREGATOR
    )


def find_orphans(stems: list[str], wired: set[str], allowed: set[str]) -> list[str]:
    return [s for s in stems if s not in wired and s not in allowed]


def self_test() -> int:
    cases: list[tuple[list[str], set[str], set[str], list[str]]] = [
        (["a", "b", "c"], {"a"}, {"b"}, ["c"]),
        (["a"], {"a"}, set(), []),
        (["a"], set(), {"a"}, []),
        (["a", "b"], set(), set(), ["a", "b"]),
        ([], set(), set(), []),
        (["x"], {"x", "y"}, set(), []),
    ]
    ok = True
    for stems, wired, allowed, want in cases:
        got = find_orphans(stems, wired, allowed)
        if got != want:
            print(f"self-test mismatch want={want} got={got}", file=sys.stderr)
            ok = False
    # sibling AND `../`-prefixed include forms must both yield the bare stem.
    if PATH_INCLUDE.findall('#[path = "regression_sigv4_known_answer.rs"]') != [
        "regression_sigv4_known_answer"
    ]:
        print("self-test: sibling PATH_INCLUDE regex broken", file=sys.stderr)
        ok = False
    if PATH_INCLUDE.findall('#[path = "../regression_oob_fail_closed.rs"]') != [
        "regression_oob_fail_closed"
    ]:
        print("self-test: parent-dir PATH_INCLUDE regex broken", file=sys.stderr)
        ok = False
    if TEST_FLAG.findall("cargo test -p keyhog-verifier --test all_tests x") != [
        "all_tests"
    ]:
        print("self-test: TEST_FLAG regex broken", file=sys.stderr)
        ok = False
    print("self-test PASS" if ok else "self-test FAIL", file=sys.stderr)
    return 0 if ok else 1


def main(argv: list[str]) -> int:
    if "--self-test" in argv:
        return self_test()
    files = top_level_test_files()
    orphans = find_orphans(files, wired_stems(), ALLOWED)
    if orphans:
        print(
            f"FAIL - {len(orphans)} CI-orphan verifier test file(s) that never run in CI:",
            file=sys.stderr,
        )
        for stem in orphans:
            print(f"  {TESTS_REL}/{stem}.rs", file=sys.stderr)
        print(
            "\nWire each into crates/verifier/tests/all_tests.rs with a "
            '`#[path = "<name>.rs"] pub mod <name>;` line (the aggregated target '
            "CI runs), or add an explicit `--test <name>` workflow step. An "
            "orphan test's assertions are dead weight and the regression it "
            "guards can ship silently.",
            file=sys.stderr,
        )
        return 1
    print(f"OK - all {len(files)} top-level verifier test files are CI-wired.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
