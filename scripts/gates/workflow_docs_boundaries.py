#!/usr/bin/env python3
"""Keep Action, direct CI, and inventory documentation in separate contracts."""

from __future__ import annotations

import pathlib
import re
import sys

REPO = pathlib.Path(__file__).resolve().parents[2]
PATHS = {
    "readme": REPO / "README.md",
    "summary": REPO / "docs" / "src" / "SUMMARY.md",
    "action": REPO / "docs" / "src" / "workflows" / "github-action.md",
    "ci": REPO / "docs" / "src" / "workflows" / "ci.md",
    "mass": REPO / "docs" / "src" / "guides" / "mass-scanning.md",
}

REQUIRED_TEXT = {
    "readme": (
        "https://santhreal.github.io/keyhog/workflows/github-action.html",
        "https://santhreal.github.io/keyhog/workflows/ci.html",
        "https://santhreal.github.io/keyhog/guides/mass-scanning.html",
    ),
    "summary": (
        "[GitHub Action secret scanning](./workflows/github-action.md)",
        "[CI secret scanning](./workflows/ci.md)",
        "[Mass repository and cloud inventory scanning](./guides/mass-scanning.md)",
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
    """Read the five public surfaces that establish workflow ownership."""
    return {name: path.read_text(encoding="utf-8") for name, path in PATHS.items()}


def boundary_issues(texts: dict[str, str]) -> list[str]:
    """Return missing routes and headings that cross a canonical workflow boundary."""
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
    print("OK - Action, direct CI, and mass-scanning documentation boundaries are explicit.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
