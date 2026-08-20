#!/usr/bin/env python3
"""Reject stale deferral and retired-backlog markers in shipped surfaces."""

from __future__ import annotations

import pathlib
import re
import sys

REPO = pathlib.Path(__file__).resolve().parents[2]

ROOTS = [
    "crates/cli/src",
    "crates/core/src",
    "crates/scanner/src",
    "crates/sources/src",
    "crates/verifier/src",
    "scripts",
    "benchmarks/README.md",
    "benchmarks/bench",
    "benchmarks/generators",
    "ml",
    ".github",
    "install.sh",
    "install.ps1",
]

SKIP_DIR_PARTS = {
    "__pycache__",
    ".pytest_cache",
    "target",
    "tests",
}

TEXT_SUFFIXES = {
    ".md",
    ".ps1",
    ".py",
    ".rs",
    ".sh",
    ".toml",
    ".txt",
    ".yaml",
    ".yml",
}

PATTERNS = [
    (re.compile(r"\bNot yet applied\b"), "replace stale queue wording with current status"),
    (re.compile(r"\btracked as backlog\b", re.I), "state the current owner/contract"),
    (re.compile(r"\btracked in the backlog\b", re.I), "state the current owner/contract"),
    (re.compile(r"\bbacklog\s+[A-Z]+-\d+\b"), "retarget retired backlog IDs to current tests or the execution plan"),
    (re.compile(r"\bdeferred to\s+[A-Z0-9_-]+\b", re.I), "state the current contract or leave a failing test"),
    (re.compile(r"\bdeferred-no-contract\b", re.I), "detectors need executable contracts, not deferred markers"),
    (re.compile(r"\bqueued for a later release\b", re.I), "state the shipped contract"),
]

ALLOW_FILES: dict[str, str] = {
    "scripts/gates/no_deferral_markers.py": "gate source definition containing deferral pattern regexes",
}


def validate_allowlists(repo: pathlib.Path = REPO) -> list[str]:
    """Validate that roots and allowlist files exist and carry written reasons."""
    errors: list[str] = []
    for root in ROOTS:
        path = repo / root
        if not path.exists():
            errors.append(f"configured scan ROOT does not exist on disk: {root}")
    for rel_path, reason in ALLOW_FILES.items():
        path = repo / rel_path
        if not path.exists():
            errors.append(f"ALLOW_FILES target does not exist on disk: {rel_path} (reason: {reason})")
        if not reason.strip():
            errors.append(f"ALLOW_FILES entry missing written reason: {rel_path}")
    return errors


def iter_files() -> list[pathlib.Path]:
    files: list[pathlib.Path] = []
    for root in ROOTS:
        path = REPO / root
        if path.is_file():
            files.append(path)
            continue
        if not path.exists():
            continue
        for child in path.rglob("*"):
            if not child.is_file():
                continue
            rel_parts = child.relative_to(REPO).parts
            if any(part in SKIP_DIR_PARTS for part in rel_parts):
                continue
            if child.name in {"Dockerfile"} or child.suffix in TEXT_SUFFIXES:
                files.append(child)
    return files


def collect() -> list[tuple[str, int, str, str]]:
    hits: list[tuple[str, int, str, str]] = []
    for path in iter_files():
        rel = path.relative_to(REPO).as_posix()
        if rel in ALLOW_FILES:
            continue
        text = path.read_text(errors="replace")
        for lineno, line in enumerate(text.splitlines(), start=1):
            for pattern, fix in PATTERNS:
                if pattern.search(line):
                    hits.append((rel, lineno, line.strip(), fix))
    return hits


def self_test() -> int:
    samples = {
        "Not yet applied: D-OLD-1": True,
        "tracked as backlog": True,
        "tracked in the backlog": True,
        "backlog MC-07": True,
        "deferred to LR3": True,
        "deferred-no-contract": True,
        "queued for a later release": True,
        "kernel listen backlog drains": False,
        "generated backlog TSV was deleted": False,
        "tracked working-tree file": False,
    }
    ok = True
    for line, want in samples.items():
        got = any(pattern.search(line) for pattern, _fix in PATTERNS)
        if got != want:
            print(f"self-test mismatch want={want} got={got}: {line}", file=sys.stderr)
            ok = False
    print("self-test PASS" if ok else "self-test FAIL", file=sys.stderr)
    return 0 if ok else 1


def main(argv: list[str]) -> int:
    if "--self-test" in argv:
        return self_test()
    allowlist_errors = validate_allowlists()
    if allowlist_errors:
        print(
            f"FAIL - {len(allowlist_errors)} invalid scan root(s) or allowlist entry/entries:",
            file=sys.stderr,
        )
        for err in allowlist_errors:
            print(f"  {err}", file=sys.stderr)
        return 1
    hits = collect()
    if hits:
        print(
            f"FAIL - {len(hits)} stale deferral/backlog marker(s) in shipped surfaces:",
            file=sys.stderr,
        )
        for rel, lineno, line, fix in hits:
            print(f"  {rel}:{lineno}: {line}", file=sys.stderr)
            print(f"    fix: {fix}", file=sys.stderr)
        return 1
    print("OK - no stale deferral/backlog markers in shipped surfaces.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
