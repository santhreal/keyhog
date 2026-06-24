#!/usr/bin/env python3
"""Reject stale references to retired internal planning artifacts.

The execution plan is the only live internal plan. Retired planning registries,
coordination ledgers, backlog docs, and GPU rewrite notes may be mentioned only
by the execution plan itself, historical changelog entries, or tests/gates whose
job is to prove those artifacts stay absent.
"""

from __future__ import annotations

import pathlib
import re
import sys

REPO = pathlib.Path(__file__).resolve().parents[2]

PATTERNS = [
    "docs/legendary",
    "GPU_DETECTION_REWRITE",
    "ALL_VECTORS_GAPS",
    "RECALL_GAP",
    "backlog/",
    "audits/",
    "GAP_FINDINGS",
    "coordination/rounds",
    "adjudication_decision_inventory",
]

ALLOWED = {
    "CHANGELOG.md",
    "docs/EXECUTION_PLAN.md",
    "crates/scanner/tests/gap/findings_registry_integrity.rs",
    "tools/ci-operability/tests/gap/execution_plan_hunt_inventory.rs",
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
    files: list[pathlib.Path] = []
    for path in REPO.rglob("*"):
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
    return hits


def self_test() -> int:
    samples = {
        "see docs/legendary/20_detection.md": True,
        "open GAP_FINDINGS.toml": True,
        "write coordination/rounds/R5.md": True,
        "normal docs/EXECUTION_PLAN.md reference": False,
        "Druid coordinator string is unrelated": False,
    }
    ok = True
    for line, want in samples.items():
        got = any(pattern in line for pattern in PATTERNS)
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
            "\nRetarget current facts to docs/EXECUTION_PLAN.md or delete historical planning references.",
            file=sys.stderr,
        )
        return 1
    print("OK - no stale internal planning references outside allowed contracts.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
