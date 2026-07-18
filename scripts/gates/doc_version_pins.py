#!/usr/bin/env python3
"""Gate: documented keyhog version pins must resolve to a real release.

Two doc patterns repeatedly drifted to a version that had no release, hard
-failing every user who pasted the snippet (the @v0.5.41 incident, KH-1358/1362):

  * a GitHub Action pin  `uses: santhreal/keyhog[...]@<ref>`
  * a pinned install tag `TAG=<ref>`

A pin is only safe if it is the floating major tag `v<MAJOR>` (which the release
process always advances to the newest release) or the exact current workspace
version `v<MAJOR.MINOR.PATCH>`. Anything else - a future patch, a stale tag - is
a dangling pin. This gate reads the workspace version and fails on any dangling
pin in the canonical docs. It is static (no network), so it never flakes.

  scripts/gates/doc_version_pins.py             # check the repo
  scripts/gates/doc_version_pins.py --self-test # prove the gate catches a bad pin
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]

ACTION_PIN = re.compile(r"santhreal/keyhog(?:/[^@\s]*)?@(v[0-9][\w.\-]*)")
INSTALL_TAG = re.compile(r"\bTAG=(v[0-9][\w.\-]*)")


def workspace_version(cargo_toml: str) -> str:
    in_pkg = False
    for line in cargo_toml.splitlines():
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            in_pkg = stripped == "[workspace.package]"
            continue
        if in_pkg:
            m = re.match(r'version\s*=\s*"([^"]+)"', stripped)
            if m:
                return m.group(1)
    raise SystemExit("could not read [workspace.package].version from Cargo.toml")


def allowed_refs(version: str) -> set[str]:
    major = version.split(".", 1)[0]
    return {f"v{major}", f"v{version}"}


def scan_text(text: str, version: str) -> list[str]:
    """Return a list of offending pins found in one document's text."""
    allowed = allowed_refs(version)
    bad: list[str] = []
    for ref in ACTION_PIN.findall(text):
        if ref not in allowed:
            bad.append(f"action pin @{ref}")
    for ref in INSTALL_TAG.findall(text):
        # An install tag must be the exact release, never a floating major.
        if ref != f"v{version}":
            bad.append(f"install TAG={ref}")
    return bad


def canonical_docs() -> list[Path]:
    docs = [REPO / "README.md", REPO / ".github/actions/keyhog/README.md"]
    docs += sorted((REPO / "docs/src").rglob("*.md"))
    return [p for p in docs if p.is_file()]


def check_repo() -> int:
    version = workspace_version((REPO / "Cargo.toml").read_text())
    allowed = allowed_refs(version)
    failures: list[str] = []
    for path in canonical_docs():
        for offense in scan_text(path.read_text(), version):
            rel = path.relative_to(REPO)
            failures.append(f"{rel}: {offense}")
    if failures:
        print(
            "FAIL - documented keyhog version pins do not resolve to a release.\n"
            f"  workspace version {version}; allowed pins: "
            f"{', '.join('@' + r for r in sorted(allowed))} "
            f"(install TAG must be v{version}).",
            file=sys.stderr,
        )
        for f in failures:
            print(f"  {f}", file=sys.stderr)
        return 1
    print(
        f"OK - all documented action pins and install tags resolve to v{version} "
        f"or the floating v{version.split('.', 1)[0]}."
    )
    return 0


def self_test() -> int:
    version = "0.5.41"
    good = (
        "uses: santhreal/keyhog@v0\n"
        "uses: santhreal/keyhog/.github/actions/keyhog@v0.5.41\n"
        "TAG=v0.5.41\n"
    )
    bad = (
        "uses: santhreal/keyhog/.github/actions/keyhog@v0.5.99\n"
        "TAG=v0.6.0\n"
    )
    assert scan_text(good, version) == [], "good pins wrongly flagged"
    offenses = scan_text(bad, version)
    assert any("@v0.5.99" in o for o in offenses), "missed a dangling action pin"
    assert any("TAG=v0.6.0" in o for o in offenses), "missed a dangling install tag"
    # A floating major is valid for an action pin but NOT for an install tag.
    assert scan_text("TAG=v0\n", version) == ["install TAG=v0"], (
        "install TAG must reject a floating major"
    )
    print("self-test OK - gate catches dangling pins, accepts v0 and the current version")
    return 0


if __name__ == "__main__":
    if "--self-test" in sys.argv[1:]:
        raise SystemExit(self_test())
    raise SystemExit(check_repo())
