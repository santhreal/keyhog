#!/usr/bin/env python3
"""Fail if any standalone test file in an enforced crate is a CI-orphan.

Each crate's CI runs specific test targets — `cargo test -p <crate> --test
all_tests` (+ a handful of explicit `--test <name>` steps and `--lib`). There is
NO `cargo test --workspace`/nextest all-target run. So a top-level
`crates/<crate>/tests/*.rs` compiles as its OWN separate integration-test target
that runs ONLY if it is reachable from the `all_tests` module tree (as a
`#[path]` include OR a plain `[pub] mod X;` sibling declaration in the crate-root
`all_tests.rs` — both wire a sibling `tests/X.rs`) or is named by a `--test`
step. Otherwise its `#[test]`s never run and the regression it guards can ship
silently.

This generalises `recall_locks_wired.py` (scanner-only, `regression_*` only) to
EVERY top-level `tests/*.rs` of the ENFORCED crates below, modelling all three
wiring mechanisms. Crates are added to `ENFORCED_CRATES` only once fully wired
(the verifier + core orphan sweeps); cli/sources still carry a large orphan
backlog and are enforced as each is swept.

A file `crates/<crate>/tests/<stem>.rs` is wired iff its stem is:
  * captured by a `#[path = "…/<stem>.rs"]` include in ANY `.rs` under the
    crate's tests tree, OR
  * declared as `[pub] mod <stem>;` in that crate's `tests/all_tests.rs`
    (the aggregator crate-root; a sibling `mod` there compiles the top-level
    file), OR
  * named by a `--test <stem>` flag in any .github/workflows/*.yml step.
`all_tests.rs` itself is the aggregator root (run directly) and is excluded.
"""

from __future__ import annotations

import pathlib
import re
import subprocess
import sys

REPO = pathlib.Path(__file__).resolve().parents[2]
WORKFLOWS = REPO / ".github/workflows"

# Crates whose top-level test files are fully wired and must STAY wired. Add a
# crate here only after its orphan sweep lands (else this gate turns CI red).
ENFORCED_CRATES: list[str] = ["verifier", "core"]

AGGREGATOR = "all_tests"

# {crate: {stem, ...}} intentionally-unaggregated files that run in CI by another
# explicit means. Keep tiny and justified.
ALLOWED: dict[str, set[str]] = {}

PATH_INCLUDE = re.compile(r'#\[path\s*=\s*"(?:[^"]*/)?([A-Za-z0-9_]+)\.rs"\]')
MOD_DECL = re.compile(r"^\s*(?:pub\s+)?mod\s+([A-Za-z0-9_]+)\s*;", re.MULTILINE)
TEST_FLAG = re.compile(r"--test\s+([A-Za-z0-9_]+)")


def workflow_test_flags() -> set[str]:
    stems: set[str] = set()
    if WORKFLOWS.is_dir():
        for wf in sorted(WORKFLOWS.glob("*.yml")):
            stems |= set(TEST_FLAG.findall(wf.read_text()))
    return stems


def wired_stems(crate: str, workflow_flags: set[str]) -> set[str]:
    tests_dir = REPO / "crates" / crate / "tests"
    stems: set[str] = set(workflow_flags)
    if tests_dir.is_dir():
        for rs in tests_dir.rglob("*.rs"):
            stems |= set(PATH_INCLUDE.findall(rs.read_text()))
        aggregator = tests_dir / f"{AGGREGATOR}.rs"
        if aggregator.exists():
            # A `[pub] mod X;` in the aggregator crate-root compiles sibling
            # `tests/X.rs`. Directory-module names (adversarial, regression …)
            # also match but never collide with a top-level file stem.
            stems |= set(MOD_DECL.findall(aggregator.read_text()))
    return stems


def top_level_test_files(crate: str) -> list[str]:
    tests_rel = f"crates/{crate}/tests"
    try:
        listing = subprocess.run(
            ["git", "-C", str(REPO), "ls-files", "-z", f"{tests_rel}/*.rs"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout
        rels = [r for r in listing.split("\0") if r]
    except (OSError, subprocess.CalledProcessError):
        rels = [
            p.relative_to(REPO).as_posix()
            for p in (REPO / tests_rel).glob("*.rs")
        ]
    depth = tests_rel.count("/") + 1
    return sorted(
        stem
        for r in rels
        if r.count("/") == depth and r.endswith(".rs")
        for stem in [r.rsplit("/", 1)[-1][: -len(".rs")]]
        if stem != AGGREGATOR
    )


def crate_orphans(crate: str, workflow_flags: set[str]) -> list[str]:
    wired = wired_stems(crate, workflow_flags)
    allowed = ALLOWED.get(crate, set())
    return [
        s
        for s in top_level_test_files(crate)
        if s not in wired and s not in allowed
    ]


def self_test() -> int:
    ok = True
    # #[path] sibling AND `../`-prefixed forms → bare stem.
    if PATH_INCLUDE.findall('#[path = "regression_sigv4_known_answer.rs"]') != [
        "regression_sigv4_known_answer"
    ]:
        print("self-test: sibling PATH_INCLUDE broken", file=sys.stderr)
        ok = False
    if PATH_INCLUDE.findall('#[path = "../regression_oob_fail_closed.rs"]') != [
        "regression_oob_fail_closed"
    ]:
        print("self-test: parent PATH_INCLUDE broken", file=sys.stderr)
        ok = False
    # `pub mod X;` and `mod X;` sibling declarations.
    if MOD_DECL.findall("pub mod detector_corpus_integrity;\nmod wave9_edge;") != [
        "detector_corpus_integrity",
        "wave9_edge",
    ]:
        print("self-test: MOD_DECL broken", file=sys.stderr)
        ok = False
    if TEST_FLAG.findall("cargo test -p keyhog-verifier --test break_it x") != [
        "break_it"
    ]:
        print("self-test: TEST_FLAG broken", file=sys.stderr)
        ok = False
    # orphan set math: a file wired by ANY mechanism is not an orphan.
    wired = {"a", "c"}
    got = [s for s in ["a", "b", "c", "d"] if s not in wired and s not in set()]
    if got != ["b", "d"]:
        print(f"self-test: orphan math broken got={got}", file=sys.stderr)
        ok = False
    print("self-test PASS" if ok else "self-test FAIL", file=sys.stderr)
    return 0 if ok else 1


def main(argv: list[str]) -> int:
    if "--self-test" in argv:
        return self_test()
    workflow_flags = workflow_test_flags()
    failed = False
    total = 0
    for crate in ENFORCED_CRATES:
        files = top_level_test_files(crate)
        total += len(files)
        orphans = crate_orphans(crate, workflow_flags)
        if orphans:
            failed = True
            print(
                f"FAIL - {len(orphans)} CI-orphan test file(s) in `{crate}` that never run in CI:",
                file=sys.stderr,
            )
            for stem in orphans:
                print(f"  crates/{crate}/tests/{stem}.rs", file=sys.stderr)
    if failed:
        print(
            "\nWire each into its crate's tests/all_tests.rs with a "
            "`pub mod <name>;` (sibling) or `#[path] pub mod <name>;` line (the "
            "aggregated target CI runs), or add an explicit `--test <name>` "
            "workflow step. An orphan test's assertions are dead weight and the "
            "regression it guards can ship silently.",
            file=sys.stderr,
        )
        return 1
    print(
        f"OK - all {total} top-level test files across {ENFORCED_CRATES} are CI-wired."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
