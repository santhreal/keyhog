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
    "daemon": REPO / "docs" / "src" / "workflows" / "daemon.md",
    "backends": REPO / "docs" / "src" / "backends.md",
    "install": REPO / "docs" / "src" / "install.md",
    "introduction": REPO / "docs" / "src" / "introduction.md",
    "workloads": REPO / "docs" / "src" / "workloads.md",
    "coverage": REPO / "docs" / "src" / "reference" / "coverage-truth.md",
    "file_shapes": REPO / "docs" / "src" / "guides" / "file-shapes.md",
}

PUBLISH_SCRIPT = REPO / "scripts" / "publish.sh"

REQUIRED_TEXT = {
    "readme": (
        "https://santhreal.github.io/keyhog/capabilities.html",
        "https://santhreal.github.io/keyhog/recipes.html",
        "https://santhreal.github.io/keyhog/workflows/github-action.html",
        "https://santhreal.github.io/keyhog/workflows/ci.html",
        "https://santhreal.github.io/keyhog/guides/mass-scanning.html",
        "https://santhreal.github.io/keyhog/releasing.html",
        "### Scan every supported source boundary",
        "## GPU-backed mass daemon workers",
        "`--daemon=mass` is a required route. It never retries in process.",
        "bounded to 8 MiB and 1,024 chunks, independent of total input size",
        "--github-collaboration",
        "--azure-container-url",
    ),
    "summary": (
        "[Choose a scanning workflow](./capabilities.md)",
        "[Source and endpoint recipes](./recipes.md)",
        "[GitHub Action secret scanning](./workflows/github-action.md)",
        "[CI secret scanning](./workflows/ci.md)",
        "[Mass repository and cloud scanning](./guides/mass-scanning.md)",
        "[GPU-backed daemon file queues](./workflows/daemon.md)",
        "[Releases](./releasing.md)",
    ),
    "chooser": (
        "[GitHub Action](./workflows/github-action.md)",
        "[CI secret scanning](./workflows/ci.md)",
        "[Mass scanning](./guides/mass-scanning.md)",
        "[Your first scan](./first-scan.md)",
        "[Daemon and warm scans](./workflows/daemon.md)",
        "[System-wide triage](./guides/system-wide-triage.md)",
        "repository object database",
        "containing only skipped binaries exits `13`",
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
        "bounded by max_commits",
        "eligible mounts and discovered Git history",
        "advisory skip gaps",
    ),
    "release": (
        "## Release a push",
        "successful `main` CI run",
        "trusted publisher",
        "`rust-lang/crates-io-auth-action`",
        "lightweight version tag",
        "make release-check",
    ),
    "action": (
        "[CI integration guide](./ci.md)",
        "[mass-scanning guide](../guides/mass-scanning.md)",
        "one checked-out repository path",
        "published Action ref installs its exact KeyHog crate with the lean `ci` feature",
        "branch or commit ref builds the checked-out portable source profile",
    ),
    "ci": (
        "[GitHub Action guide](./github-action.md)",
        "[mass-scanning guide](../guides/mass-scanning.md)",
        "published refs install the lean `ci` feature",
        "output-path failure exits `2`",
        "Repository object database",
    ),
    "mass": (
        "[GitHub Action guide](../workflows/github-action.md)",
        "[CI integration guide](../workflows/ci.md)",
        "too large or too independent for one repository gate",
        "### GPU-backed daemon worker",
        "keyhog daemon start --mass",
        "The completion receipt contains exact total and GPU batches, chunks, bytes",
        "--mass-gpu-primary",
        "gpu-metal-region-presence",
        "without copying payload bytes through IPC",
        "until a configured page, object, byte, or source limit binds",
    ),
    "daemon": (
        "## GPU-backed mass worker",
        "keyhog calibrate-autoroute --policy default",
        "gpu-wgpu-region-presence",
        "gpu-cuda-region-presence",
        "gpu-metal-region-presence",
        "The completion receipt records exact total and GPU batches, chunks, bytes",
        "--mass-gpu-primary",
        "payload bytes remain in the daemon process",
    ),
    "backends": (
        "CUDA, native Metal, and WGPU are acquired and measured independently",
        "`gpu-cuda`, `gpu-metal`, or `gpu-wgpu`",
    ),
    "install": (
        "cargo install --locked --version '=",
        "--no-default-features --features portable,gpu",
        "--no-default-features --features portable,simd",
        "--features ci",
        "`ci-lean` is a broad maintainer test closure",
        "Cargo does not execute the binary after installation",
        "historical binary-asset channel",
        "does not publish binary release assets or installer bundles",
    ),
    "introduction": (
        "sample below comes from a `portable,simd` build",
        "default crates.io install reports the pure-Rust CPU route",
        "No hosted scanning agent",
    ),
    "workloads": (
        "Required build",
        "portable` or `ci,git",
        "--no-default-excludes",
        "`keyhog scan --help` is authoritative",
        "Advisory skips can leave",
    ),
    "coverage": (
        "read-nothing scan exits `13`",
        "directory containing only skipped binaries",
        "mixed tree can exit `0` with this advisory row",
        "unwritable output path exits `2`",
    ),
    "file_shapes": (
        "keyhog scan dist/app.min.js",
        "keyhog scan dist/ --no-default-excludes",
        "explicit file request is not removed",
    ),
}

FORBIDDEN_HEADINGS = {
    "action": re.compile(r"^## (?:GitLab CI|CircleCI|Jenkins|Buildkite|Mass scanning)$", re.M),
    "ci": re.compile(r"^## (?:Inputs|Outputs|Scan a monorepo|Adopt KeyHog without blocking existing findings)$", re.M),
    "mass": re.compile(r"^## (?:Inputs|Outputs|Pin Action code and scanner releases|GitHub Actions)$", re.M),
}

FORBIDDEN_TEXT = {
    "action": (
        "installs an authenticated KeyHog release",
    ),
    "ci": (
        "~/.local/bin/keyhog",
        "Published Action refs install KeyHog from crates.io and build the full default feature set",
    ),
    "coverage": (
        "all-binary directory reports a clean scan it never performed",
        "output-path failure, which exits `3`",
    ),
}


def canonical_texts() -> dict[str, str]:
    """Read the public surfaces that establish use-case discovery and ownership."""
    return {name: path.read_text(encoding="utf-8") for name, path in PATHS.items()}


def published_crates() -> tuple[str, ...]:
    """Return the publication-order crate list owned by scripts/publish.sh."""
    publish_script = PUBLISH_SCRIPT.read_text(encoding="utf-8")
    publish_match = re.search(r"^CRATES=\(([^)]*)\)$", publish_script, re.MULTILINE)
    return tuple(publish_match.group(1).split()) if publish_match else ()


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
    for name, forbidden in FORBIDDEN_TEXT.items():
        text = texts.get(name, "")
        for needle in forbidden:
            if needle in text:
                issues.append(f"{name}: stale or unsafe workflow claim {needle!r}")
    release = texts.get("release", "")
    crates = published_crates()
    if not crates:
        issues.append("release: scripts/publish.sh does not expose the canonical CRATES list")
    else:
        for crate in crates:
            if f"`{crate}`" not in release:
                issues.append(
                    f"release: published crate {crate!r} is missing from the release guide"
                )
    if "Set the repository Actions secret `CARGO_REGISTRY_TOKEN`" in release:
        issues.append(
            "release: guide still requires a long-lived crates.io token instead of trusted publishing"
        )
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
