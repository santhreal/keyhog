#!/usr/bin/env python3
"""Fail if any standalone scanner test file is a CI-orphan.

CI runs the scanner integration suite through ONE aggregator step,
`cargo test -p keyhog-scanner --test all_tests`, plus a handful of explicit
`--test <name>` steps in the workflows. A `crates/scanner/tests/*.rs`
file that is neither `#[path]`-included in `all_tests.rs` nor named by a `--test`
step never runs in CI: its assertions are dead weight, and the very
recall/precision regression it was written to catch can ship unnoticed. (This
gate exists because ~36 recall locks were authored and committed over many tasks
but wired NOWHERE, they only ran on the author's laptop.)

A file is considered wired if its module stem is either:
  * `#[path = "<stem>.rs"]`-included in crates/scanner/tests/all_tests.rs, or
  * named by a `--test <stem>` flag in any .github/workflows/*.yml step.
"""

from __future__ import annotations

import pathlib
import re
import subprocess
import sys

REPO = pathlib.Path(__file__).resolve().parents[2]
TESTS_REL = "crates/scanner/tests"
ALL_TESTS = REPO / TESTS_REL / "all_tests.rs"
WORKFLOWS = REPO / ".github/workflows"

# Test files intentionally NOT aggregated in all_tests.rs because they need a
# GPU host, release-timing harness, all-backend availability, or have module
# declarations that conflict with the aggregator's `mod support`. Each entry is
# a promise the file runs in CI by some other means (bespoke --test step, nightly,
# or a future GPU-CI lane). Keep this tiny and justified.
ALLOWED: dict[str, str] = {
    "gpu_ac_recall_bug_56": "GPU host required",
    "gpu_ac_smoke": "GPU host required",
    "gpu_entropy_recall_parity": "GPU host required",
    "gpu_peer_backend_parity": "GPU host required",
    "gpu_parity": "GPU host required",
    "gpu_proptest_invariants": "GPU host required",
    "gpu_region_overfire_validation": "GPU host required",
    "gpu_resident_output_ownership": "GPU host required",
    "packed_gpu_vyre_artifact": "GPU host required",
}

PATH_INCLUDE = re.compile(r'#\[path\s*=\s*"([A-Za-z0-9_]+)\.rs"\]')
TEST_FLAG = re.compile(r"--test\s+([A-Za-z0-9_]+)")


def wired_stems() -> set[str]:
    stems: set[str] = set()
    if ALL_TESTS.exists():
        stems |= set(PATH_INCLUDE.findall(ALL_TESTS.read_text()))
    if WORKFLOWS.is_dir():
        for wf in sorted(WORKFLOWS.glob("*.yml")):
            stems |= set(TEST_FLAG.findall(wf.read_text()))
    return stems

def toplevel_test_files() -> list[str]:
    """Git-tracked top-level `*.rs` files under the scanner tests dir.

    Tracks the committed tree (matching CI's clean checkout) so a developer's
    untracked scratch test cannot trip the gate. Excludes `all_tests.rs`
    (the aggregator itself) and `testing.rs` (a compile-only helper).
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
        rels = [
            p.relative_to(REPO).as_posix()
            for p in (REPO / TESTS_REL).glob("*.rs")
        ]
    # Top level only: a file inside a subdir is a module of a `#[path]`-included
    # parent, not a standalone integration target.
    return sorted(
        r.rsplit("/", 1)[-1][: -len(".rs")]
        for r in rels
        if r.count("/") == TESTS_REL.count("/") + 1
        and r.endswith(".rs")
        and r.rsplit("/", 1)[-1] not in ("all_tests.rs", "testing.rs")
    )
def validate_allowlists(test_stems: list[str], wired: set[str]) -> list[str]:
    """Validate that allowlist stems exist on disk and are not redundantly wired."""
    errors: list[str] = []
    file_set = set(test_stems)
    for stem, reason in ALLOWED.items():
        if stem not in file_set:
            errors.append(f"ALLOWED stem does not exist as test file: {TESTS_REL}/{stem}.rs (reason: {reason})")
        if not reason.strip():
            errors.append(f"ALLOWED entry missing written reason: {stem}")
        if stem in wired:
            errors.append(f"ALLOWED entry is stale (already wired in CI): {stem}")
    return errors


def find_orphans(
    test_stems: list[str], wired: set[str], allowed: set[str] | dict[str, str] = ALLOWED
) -> list[str]:
    allowed_stems = set(allowed.keys()) if isinstance(allowed, dict) else set(allowed)
    return [s for s in test_stems if s not in wired and s not in allowed_stems]


def self_test() -> int:
    cases: list[tuple[list[str], set[str], set[str], list[str]]] = [
        # (test_stems, wired, allowed, expected_orphans)
        (["regression_a", "regression_b", "regression_c"], {"regression_a"}, {"regression_b"}, ["regression_c"]),
        (["regression_a"], {"regression_a"}, set(), []),
        (["regression_a"], set(), {"regression_a"}, []),
        (["regression_a", "regression_b"], set(), set(), ["regression_a", "regression_b"]),
        ([], set(), set(), []),
        (["regression_x"], {"regression_x", "regression_y"}, set(), []),
    ]
    ok = True
    for stems, wired, allowed, want in cases:
        got = find_orphans(stems, wired, allowed)
        if got != want:
            print(f"self-test mismatch want={want} got={got}", file=sys.stderr)
            ok = False
    # regex extractors must find real wiring forms
    if PATH_INCLUDE.findall('#[path = "regression_foo_recall.rs"]') != ["regression_foo_recall"]:
        print("self-test: PATH_INCLUDE regex broken", file=sys.stderr)
        ok = False
    if TEST_FLAG.findall("cargo test -p x --test regression_bar_recall other") != ["regression_bar_recall"]:
        print("self-test: TEST_FLAG regex broken", file=sys.stderr)
        ok = False
    print("self-test PASS" if ok else "self-test FAIL", file=sys.stderr)
    return 0 if ok else 1


def main(argv: list[str]) -> int:
    if "--self-test" in argv:
        return self_test()
    files = toplevel_test_files()
    wired = wired_stems()
    allowlist_errors = validate_allowlists(files, wired)
    if allowlist_errors:
        print(
            f"FAIL - {len(allowlist_errors)} invalid or stale allowlist entry/entries:",
            file=sys.stderr,
        )
        for err in allowlist_errors:
            print(f"  {err}", file=sys.stderr)
        return 1
    orphans = find_orphans(files, wired, ALLOWED)
    if orphans:
        print(
            f"FAIL - {len(orphans)} CI-orphan scanner test(s) that never run in CI:",
            file=sys.stderr,
        )
        for stem in orphans:
            print(f"  {TESTS_REL}/{stem}.rs", file=sys.stderr)
        print(
            "\nWire each into crates/scanner/tests/all_tests.rs with a "
            '`#[path = "<name>.rs"] pub mod <name>;` line (the aggregator CI '
            "runs), or add an explicit `--test <name>` workflow step, or add "
            "the stem to ALLOWED in this script with a justification. An orphan "
            "test's assertions are dead weight and the regression it guards can "
            "ship silently.",
            file=sys.stderr,
        )
        return 1
    print(f"OK - all {len(files)} scanner test files are CI-wired.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
