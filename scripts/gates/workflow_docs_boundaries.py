#!/usr/bin/env python3
"""Keep operator use cases discoverable without merging distinct workflow contracts."""

from __future__ import annotations

import pathlib
import re
import sys

REPO = pathlib.Path(__file__).resolve().parents[2]
PATHS = {
    "readme": REPO / "README.md",
    "summary": REPO / "docs" / "src" / "SUMMARY.md",
    "chooser": REPO / "docs" / "src" / "capabilities.md",
    "recipes": REPO / "docs" / "src" / "recipes.md",
    "release": REPO / "docs" / "src" / "releasing.md",
    "action": REPO / "docs" / "src" / "workflows" / "github-action.md",
    "ci": REPO / "docs" / "src" / "workflows" / "ci.md",
    "mass": REPO / "docs" / "src" / "guides" / "mass-scanning.md",
}

REQUIRED_TEXT = {
    "readme": (
        "https://santhreal.github.io/keyhog/capabilities.html",
        "https://santhreal.github.io/keyhog/recipes.html",
        "https://santhreal.github.io/keyhog/workflows/github-action.html",
        "https://santhreal.github.io/keyhog/workflows/ci.html",
        "https://santhreal.github.io/keyhog/guides/mass-scanning.html",
        "https://santhreal.github.io/keyhog/releasing.html",
    ),
    "summary": (
        "[Choose a scanning workflow](./capabilities.md)",
        "[Recipes](./recipes.md)",
        "[GitHub Action secret scanning](./workflows/github-action.md)",
        "[CI secret scanning](./workflows/ci.md)",
        "[Mass repository and cloud inventory scanning](./guides/mass-scanning.md)",
        "[Prepare and publish a release](./releasing.md)",
    ),
    "chooser": (
        "[GitHub Action](./workflows/github-action.md)",
        "[CI secret scanning](./workflows/ci.md)",
        "[Mass scanning](./guides/mass-scanning.md)",
        "[Your first scan](./first-scan.md)",
        "[Daemon and warm scans](./workflows/daemon.md)",
        "[System-wide triage](./guides/system-wide-triage.md)",
    ),
    "recipes": (
        "## Find the right recipe",
        "## Scan code you have locally",
        "## Gate commits and pull requests",
        "## Add it to CI (one workflow file)",
        "## Scan an entire GitHub organization",
        "## Scan a Docker image before you ship it",
        "## Audit a cloud bucket",
        "## Scan a URL, endpoint response, or HAR capture",
        "## Sweep an entire machine",
        "## Confirm a finding is a live credential",
        "## Emit for any pipeline or SIEM",
    ),
    "release": (
        "## Choose an operation",
        'scripts/release.py "$NEXT_VERSION"',
        "--ssh USER@HOST --remote-dir /absolute/keyhog/path",
        "--publish --resume",
        "configured primary-key fingerprint",
        "make -C benchmarks readme-matrix",
    ),
    "action": (
        "[CI integration guide](./ci.md)",
        "[mass-scanning guide](../guides/mass-scanning.md)",
        "one checked-out repository path",
    ),
    "ci": (
        "[GitHub Action guide](./github-action.md)",
        "[mass-scanning guide](../guides/mass-scanning.md)",
    ),
    "mass": (
        "[GitHub Action guide](../workflows/github-action.md)",
        "[CI integration guide](../workflows/ci.md)",
        "too large or too independent for one repository gate",
    ),
}

FORBIDDEN_HEADINGS = {
    "action": re.compile(r"^## (?:GitLab CI|CircleCI|Jenkins|Buildkite|Mass scanning)$", re.M),
    "ci": re.compile(r"^## (?:Inputs|Outputs|Scan a monorepo|Adopt KeyHog without blocking existing findings)$", re.M),
    "mass": re.compile(r"^## (?:Inputs|Outputs|Pin Action code and scanner releases|GitHub Actions)$", re.M),
}


def canonical_texts() -> dict[str, str]:
    """Read the public surfaces that establish use-case discovery and ownership."""
    return {name: path.read_text(encoding="utf-8") for name, path in PATHS.items()}


def boundary_issues(texts: dict[str, str]) -> list[str]:
    """Return missing use-case routes and headings that cross workflow boundaries."""
    issues: list[str] = []
    for name, required in REQUIRED_TEXT.items():
        text = " ".join(texts.get(name, "").split())
        for needle in required:
            if " ".join(needle.split()) not in text:
                issues.append(f"{name}: missing canonical workflow route {needle!r}")
    for name, pattern in FORBIDDEN_HEADINGS.items():
        text = texts.get(name, "")
        if match := pattern.search(text):
            issues.append(f"{name}: heading belongs to another workflow: {match.group(0)!r}")
    return issues


def main() -> int:
    issues = boundary_issues(canonical_texts())
    if issues:
        print(f"FAIL - {len(issues)} workflow documentation boundary issue(s):", file=sys.stderr)
        for issue in issues:
            print(f"  {issue}", file=sys.stderr)
        return 1
    print("OK - operator use cases are discoverable and workflow boundaries are explicit.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
