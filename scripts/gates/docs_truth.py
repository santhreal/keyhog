#!/usr/bin/env python3
"""Prove that the canonical mdBook documentation is complete and source-true."""

from __future__ import annotations

import pathlib
import re
import subprocess
import sys
import tomllib

REPO = pathlib.Path(__file__).resolve().parents[2]
DOCS = REPO / "docs" / "src"

STALE_PATTERNS = [
    ("unsupported recall claim", re.compile(r"\b96\s*%")),
    ("unsupported recall delta", re.compile(r"\b33\s*%\s+more\b")),
    ("unsupported superlative", re.compile(r"fastest, most accurate", re.I)),
    ("startup hardware guess", re.compile(r"Auto-detects your hardware", re.I)),
    ("fallback-router claim", re.compile(r"(?:picks|routes scans to) the fastest backend", re.I)),
    ("retired benchmark path", re.compile(r"benchmark-harness/")),
    ("retired routing output", re.compile(r"routing matrix:")),
    ("duplicate website path", re.compile(r"(?:^|[(`\s])/?site/")),
]


def workspace_version() -> str:
    cargo = tomllib.loads((REPO / "Cargo.toml").read_text())
    return f"v{cargo['workspace']['package']['version']}"


def detector_count() -> int:
    return sum(1 for path in (REPO / "detectors").glob("*.toml") if path.is_file())


def canonical_paths() -> list[pathlib.Path]:
    paths = [REPO / "README.md", REPO / ".github" / "actions" / "keyhog" / "README.md"]
    paths.extend(sorted(DOCS.rglob("*.md")))
    paths.extend(sorted((REPO / "docs" / "assets").glob("*.svg")))
    return paths


def summary_targets() -> set[pathlib.Path]:
    summary = (DOCS / "SUMMARY.md").read_text()
    targets: set[pathlib.Path] = set()
    for target in re.findall(r"\]\(([^)#]+\.md)(?:#[^)]+)?\)", summary):
        targets.add((DOCS / target).resolve())
    return targets


def truth_issues() -> list[str]:
    issues: list[str] = []
    expected_version = workspace_version()
    keyhog_series = ".".join(expected_version.split(".")[:2]) + "."
    expected_count = detector_count()
    for path in canonical_paths():
        text = path.read_text(errors="replace")
        rel = path.relative_to(REPO).as_posix()
        for lineno, line in enumerate(text.splitlines(), 1):
            for version in re.findall(r"\bv\d+\.\d+\.\d+\b", line):
                if not version.startswith(keyhog_series):
                    continue
                if version != expected_version:
                    issues.append(f"{rel}:{lineno}: stale version {version}; expected {expected_version}")
            for count in re.findall(r"\b(\d+)\s+detectors\b", line, re.I):
                if int(count) != expected_count:
                    issues.append(
                        f"{rel}:{lineno}: stale detector count {count}; expected {expected_count}"
                    )
            for label, pattern in STALE_PATTERNS:
                if pattern.search(line):
                    issues.append(f"{rel}:{lineno}: {label}: {line.strip()}")

    summary = summary_targets()
    for page in sorted(DOCS.rglob("*.md")):
        if page.name == "SUMMARY.md":
            continue
        if page.resolve() not in summary:
            issues.append(f"{page.relative_to(REPO)}: orphaned from docs/src/SUMMARY.md")

    tracked = subprocess.run(
        ["git", "ls-files", "site", "docs/book"],
        cwd=REPO,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.splitlines()
    for path in tracked:
        issues.append(f"{path}: duplicate/generated documentation must not be tracked")
    return issues


def self_test() -> int:
    expected = workspace_version()
    count = detector_count()
    bad = f"site/config.html keyhog v0.0.0 with {count + 1} detectors picks the fastest backend"
    detected = (
        bool(STALE_PATTERNS[-1][1].search(bad))
        and bool(STALE_PATTERNS[4][1].search(bad))
        and "v0.0.0" != expected
        and count + 1 != count
    )
    print("self-test PASS" if detected else "self-test FAIL", file=sys.stderr)
    return 0 if detected else 1


def main(argv: list[str]) -> int:
    if "--self-test" in argv:
        return self_test()
    issues = truth_issues()
    if issues:
        print(f"FAIL - {len(issues)} documentation truth issue(s):", file=sys.stderr)
        for issue in issues:
            print(f"  {issue}", file=sys.stderr)
        return 1
    print("OK - canonical mdBook documentation is complete and source-true.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
