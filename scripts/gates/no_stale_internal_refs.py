#!/usr/bin/env python3
"""Reject stale references to retired internal planning artifacts.

All internal planning artifacts -- the former execution plan, retired planning
registries, coordination ledgers, backlog docs, and GPU rewrite notes -- are
purged from this public repo (the plan leaked operator machine paths). They may
be mentioned only by historical changelog entries or by the absence-guard
tests/gates whose job is to prove they stay gone. A fresh reference to any of
them is a coherence regression -- a pointer to a file that no public reader can
open.
"""

from __future__ import annotations

import pathlib
import re
import subprocess
import sys

REPO = pathlib.Path(__file__).resolve().parents[2]

PATTERNS = [
    "EXECUTION_PLAN",
    "BACKLOG.md",
    "planning/vyre-acceleration",
    "docs/legendary",
    "GPU_DETECTION_REWRITE",
    "ALL_VECTORS_GAPS",
    "RECALL_GAP",
    "backlog/",
    "audits/",
    "GAP_FINDINGS",
    "coordination/rounds",
    "adjudication_decision_inventory",
    "TESTING_PROGRAM",
    "TODO.md",
    "FP_AUDIT_REPORT",
    "cli-surface-bloat.md",
]

# Distinctive internal-planning *content* markers (not just filenames). These
# phrases belong to phase-design docs, session logs, and triage ledgers and
# never appear in consumer or contributor reference docs. They catch an internal
# planning doc dropped into the tree even when it names no purged file -- the gap
# that once let `autoroute-calibration-phase.md` and a Gemini triage sweep ship
# in `docs/`. Each is specific enough not to collide with legitimate prose
# (e.g. bare "audit"/"triage"/"phase" stay allowed; only these exact phrasings
# trip the gate).
CONTENT_PATTERNS = [
    re.compile(r"Phase Design"),
    re.compile(r"Phase tasks"),
    re.compile(r"task list #\d"),
    re.compile(r"Session findings"),
    re.compile(r"drive #\d"),
    re.compile(r"Innovation lane"),
    re.compile(r"Pending-wire"),
    re.compile(r"ugliness sweep"),
    re.compile(r"REACHED, built"),
    re.compile(r"everything wired so far"),
]

ALLOWED = {
    ".gitignore",
    "CHANGELOG.md",
    # Absence guards: these tests/gates name the retired artifacts precisely to
    # prove they stay gone.
    "crates/scanner/tests/gap/findings_registry_integrity.rs",
    "tools/ci-operability/tests/gap/execution_plan_no_retired_registry.rs",
    "scripts/gates/no_stale_internal_refs.py",
}

SKIP_DIRS = {
    ".git",
    "target",
    "vendor",
    "docs/book",
    "benchmarks/corpora",
    "benchmarks/results",
    "metrics/generated",
    "site",
}

TEXT_SUFFIXES = {
    ".bash",
    ".cfg",
    ".css",
    ".html",
    ".json",
    ".lock",
    ".md",
    ".ps1",
    ".py",
    ".rs",
    ".sh",
    ".toml",
    ".txt",
    ".wgsl",
    ".yaml",
    ".yml",
}


def is_skipped(path: pathlib.Path) -> bool:
    rel = path.relative_to(REPO).as_posix()
    return any(rel == d or rel.startswith(f"{d}/") for d in SKIP_DIRS)


def iter_files() -> list[pathlib.Path]:
    # Scan git-TRACKED files (committed + staged), not the raw working tree.
    # CI checks out a clean tree, so the two are identical there; locally this
    # keeps a developer's untracked scratch (saved `git diff`/`git status`
    # dumps, throwaway corpora) from tripping the gate on references it will
    # never ship. Falls back to a working-tree walk outside a git checkout.
    try:
        listing = subprocess.run(
            ["git", "-C", str(REPO), "ls-files", "-z"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout
        candidates = [REPO / rel for rel in listing.split("\0") if rel]
    except (OSError, subprocess.CalledProcessError):
        candidates = list(REPO.rglob("*"))
    files: list[pathlib.Path] = []
    for path in candidates:
        if not path.is_file() or is_skipped(path):
            continue
        if path.name in {".gitignore", "Dockerfile"} or path.suffix in TEXT_SUFFIXES:
            files.append(path)
    return files


def collect() -> list[tuple[str, int, str, str]]:
    hits: list[tuple[str, int, str, str]] = []
    for path in iter_files():
        rel = path.relative_to(REPO).as_posix()
        if rel in ALLOWED:
            continue
        text = path.read_text(errors="replace")
        for lineno, line in enumerate(text.splitlines(), start=1):
            for pattern in PATTERNS:
                if pattern in line:
                    hits.append((rel, lineno, pattern, line.strip()))
            for marker in CONTENT_PATTERNS:
                if marker.search(line):
                    hits.append((rel, lineno, marker.pattern, line.strip()))
    return hits


def self_test() -> int:
    samples = {
        "see docs/legendary/20_detection.md": True,
        "open GAP_FINDINGS.toml": True,
        "write coordination/rounds/R5.md": True,
        "see TESTING_PROGRAM.md section 3": True,
        "old backlog cli-surface-bloat.md": True,
        "see docs/EXECUTION_PLAN.md (now purged)": True,
        "see BACKLOG.md for the remaining work": True,
        "open planning/vyre-acceleration/02-keyhog-adoption-plan.md": True,
        "## Phase Design, autoroute": True,
        "Phase tasks (see task list #31-#43)": True,
        "Session findings (2026-06-27)": True,
        "empirical, drive #34/#36": True,
        "Gemini ugliness sweep, triage": True,
        "macOS: REACHED, built, dogfooded": True,
        "Druid coordinator string is unrelated": False,
        "this phase of the scan is the design": False,
        "run a security audit and triage findings": False,
    }
    ok = True
    for line, want in samples.items():
        got = any(pattern in line for pattern in PATTERNS) or any(
            marker.search(line) for marker in CONTENT_PATTERNS
        )
        if got != want:
            print(f"self-test mismatch want={want} got={got}: {line}", file=sys.stderr)
            ok = False
    print("self-test PASS" if ok else "self-test FAIL", file=sys.stderr)
    return 0 if ok else 1


def main(argv: list[str]) -> int:
    if "--self-test" in argv:
        return self_test()
    hits = collect()
    if hits:
        print(
            f"FAIL - {len(hits)} stale internal planning reference(s) outside allowed absence contracts:",
            file=sys.stderr,
        )
        for rel, lineno, pattern, line in hits:
            print(f"  {rel}:{lineno}: {pattern}: {line}", file=sys.stderr)
        print(
            "\nThese planning artifacts are purged from the public repo. Delete the "
            "reference, or -- if this file is an absence guard -- add it to ALLOWED.",
            file=sys.stderr,
        )
        return 1
    print("OK - no stale internal planning references outside allowed contracts.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
