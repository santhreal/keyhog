#!/usr/bin/env python3
"""Cheap organization audit for known KeyHog rot classes.

This is not a style gate. It rejects structural lies that previously made the
repo look healthier than it was: generated LOC-cap tests, stale current docs for
removed surfaces, unproven autoroute wording, missing or stale load-bearing
owner boundaries, and CI/Make targets that omit required competitor evidence.
"""

from __future__ import annotations

import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent

ARCHITECTURE_OWNER_HEADING = "## Load-bearing boundary owner map"
REQUIRED_ARCHITECTURE_OWNERS = (
    (
        "Marketplace metadata, documented inputs/outputs, and top-level composite steps",
        "action.yml",
    ),
    (
        "Repository-local Action metadata consumed by GitHub workflows",
        ".github/actions/keyhog/action.yml",
    ),
    (
        "Action input validation, authenticated binary acquisition, scan invocation, exit mapping, and output publication",
        ".github/actions/keyhog/run-scan.sh",
    ),
    (
        "Automatic version, changelog, and crates.io publication",
        ".github/workflows/release.yml",
    ),
    ("CLI argument dispatch and setup-error exit routing", "crates/cli/src/lib.rs::cli_main"),
    (
        "Completed-scan exit precedence",
        "crates/cli/src/orchestrator/run.rs::resolve_scan_exit",
    ),
    ("Curated source-crate export surface", "crates/sources/src/api.rs"),
    (
        "Live-verification construction and execution",
        "crates/verifier/src/lib.rs::VerificationEngine",
    ),
    (
        "Deduplicated match to report-safe finding conversion",
        "crates/core/src/finding.rs::VerifiedFinding::from_deduped",
    ),
    ("Scanner execution flow", "crates/scanner/src/engine/mod.rs"),
)

GENERATED_CACHE_DIRS = (
    ".pytest_cache",
    "benchmarks/.pytest_cache",
    "tools/secretbench/scoring/.pytest_cache",
    "crates/cli/.cache",
)

GENERATED_CACHE_GLOBS = (
    "benchmarks/**/__pycache__",
    "ml/__pycache__",
    "scripts/**/__pycache__",
    "tools/**/__pycache__",
)


def rel(path: pathlib.Path) -> str:
    return path.resolve().relative_to(ROOT).as_posix()


def text(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def fail(violations: list[str], msg: str) -> None:
    violations.append(msg)


def markdown_fence_marker(raw_line: str) -> str | None:
    stripped = raw_line.lstrip()
    for marker_char in ("`", "~"):
        marker = marker_char * 3
        if stripped.startswith(marker):
            run_len = 0
            for ch in stripped:
                if ch != marker_char:
                    break
                run_len += 1
            return marker_char * run_len
    return None


def scan_commands_under_environment_variables(path: pathlib.Path, src: str) -> list[str]:
    if path.suffix.casefold() != ".md":
        return []

    violations: list[str] = []
    in_environment_section = False
    environment_heading_level = 0
    fence_marker: str | None = None
    for line_number, raw_line in enumerate(src.splitlines(), start=1):
        marker = markdown_fence_marker(raw_line)
        if marker is not None:
            if fence_marker is None:
                fence_marker = marker
            elif marker.startswith(fence_marker):
                fence_marker = None
            continue
        if fence_marker is not None:
            if in_environment_section and re.search(r"\bkeyhog\s+scan\b", raw_line, re.IGNORECASE):
                violations.append(
                    f"CLI reference labels scan command controls as environment variables: {rel(path)}:{line_number}"
                )
            continue

        heading = re.match(r"^(#+)\s+(.*)$", raw_line)
        if heading:
            level = len(heading.group(1))
            title = heading.group(2).strip().casefold()
            if in_environment_section and level <= environment_heading_level:
                in_environment_section = False
            if level > 1 and title == "environment variables":
                in_environment_section = True
                environment_heading_level = level
            continue
        if in_environment_section and re.search(r"\bkeyhog\s+scan\b", raw_line, re.IGNORECASE):
            violations.append(
                f"CLI reference labels scan command controls as environment variables: {rel(path)}:{line_number}"
            )
    return violations


def check_no_generated_cache_clutter(violations: list[str]) -> None:
    seen: set[str] = set()
    for raw in GENERATED_CACHE_DIRS:
        path = ROOT / raw
        if path.is_dir():
            item = rel(path)
            seen.add(item)
            fail(violations, f"generated cache clutter remains: {item}")

    for pattern in GENERATED_CACHE_GLOBS:
        for path in sorted(ROOT.glob(pattern)):
            if path.is_dir():
                item = rel(path)
                if item not in seen:
                    seen.add(item)
                    fail(violations, f"generated cache clutter remains: {item}")


def check_no_loc_cap_bloat(violations: list[str]) -> None:
    for path in sorted((ROOT / "crates").glob("*/tests/unit/gates/*_file_size_cap.rs")):
        fail(violations, f"dead LOC-cap gate file remains: {rel(path)}")

    for path in sorted((ROOT / "crates").glob("*/tests/unit/gates/mod.rs")):
        src = path.read_text(encoding="utf-8")
        if "_file_size_cap" in src:
            fail(violations, f"LOC-cap gate still imported: {rel(path)}")

    stale_source_patterns = (
        "500-line modularity cap",
        "500-line cap",
        "500 line cap",
        "file line cap",
        "under 500",
        "under_500",
        "modularity cap is 500",
    )
    for path in sorted((ROOT / "crates").glob("*/src/**/*.rs")):
        src = path.read_text(encoding="utf-8")
        for pattern in stale_source_patterns:
            if pattern in src:
                fail(violations, f"source still justifies architecture by LOC cap: {rel(path)}")
                break


def check_current_claims(violations: list[str]) -> None:
    claim_paths = [
        ROOT / "README.md",
        ROOT / "scripts/dogfood-windows.ps1",
        ROOT / "crates/scanner/Cargo.toml",
        *(ROOT / "docs/src").rglob("*.md"),
        *(ROOT / "crates/cli/src").rglob("*.rs"),
        *(ROOT / "crates/scanner/src").rglob("*.rs"),
    ]
    stale_patterns = {
        r"\bkeyhog\s+tui\b": "removed TUI command is still documented",
        r"Interactive TUI": "removed TUI surface is still documented",
        r"\bGPU\s+megakernel\b": "retired GPU megakernel route is still named as live",
        r"\bgpu\s+megakernel\b": "retired GPU megakernel route is still named as live",
        r"\bmegakernel\s+producer\b": "retired megakernel producer is still named as live",
        r"\bcoalesced/megakernel\b": "retired megakernel phase-2 wording remains",
        r"\bgpu-zero-copy\b": "retired zero-copy GPU label is still named as live",
        r"batch dispatched \(gpu megakernel\)": "retired GPU megakernel routing trace remains",
        r"fused batch dispatched to GPU megakernel": "retired GPU megakernel routing trace remains",
        r"fastest hardware backend": "unproven fastest-backend claim remains",
        r"routes every scan": "unproven routing guarantee remains",
        r"\bauto-?router\b": "autorouter wording remains",
        r"\bautorouting\b": "autorouting wording remains",
    }
    for path in sorted(p for p in claim_paths if p.is_file()):
        src = path.read_text(encoding="utf-8", errors="replace")
        rel_path = rel(path)
        violations.extend(scan_commands_under_environment_variables(path, src))
        for pattern, reason in stale_patterns.items():
            if pattern == r"\bgpu-zero-copy\b" and rel_path == "crates/scanner/src/hw_probe/select.rs":
                continue
            if (
                pattern == r"\bgpu-zero-copy\b"
                and rel_path.startswith("crates/cli/src/orchestrator/dispatch/backend/tests")
                and "autoroute_cache_rejects_legacy_backend_alias_labels" in src
            ):
                continue
            if re.search(pattern, src, flags=re.IGNORECASE):
                fail(violations, f"{reason}: {rel_path}")


def architecture_code_references(src: str) -> set[str]:
    """Return repository-relative code paths named anywhere in architecture."""
    return set(
        re.findall(
            r"`((?:action\.yml|(?:\.github|scripts|crates)/)[^`\n]*)`",
            src,
        )
    )


def architecture_owner_section(src: str) -> str | None:
    if ARCHITECTURE_OWNER_HEADING not in src:
        return None
    section = src.split(ARCHITECTURE_OWNER_HEADING, 1)[1]
    return section.split("\n## ", 1)[0]


def architecture_owner_rows(src: str) -> list[tuple[str, tuple[str, ...]]]:
    """Parse boundary-to-owner associations from the dedicated Markdown table."""
    section = architecture_owner_section(src)
    if section is None:
        return []

    rows: list[tuple[str, tuple[str, ...]]] = []
    for raw_line in section.splitlines():
        stripped = raw_line.strip()
        if not (stripped.startswith("|") and stripped.endswith("|")):
            continue
        cells = [cell.strip() for cell in stripped[1:-1].split("|")]
        if len(cells) != 2 or cells[0] in {"Boundary", "---"}:
            continue
        rows.append((cells[0], tuple(sorted(architecture_code_references(cells[1])))))
    return rows




def owner_reference_violation(reference: str, root: pathlib.Path = ROOT) -> str | None:
    """Resolve one architecture path and optional symbol without trusting prose."""
    raw_path, separator, symbol = reference.partition("::")
    candidate = (root / raw_path).resolve()
    try:
        candidate.relative_to(root.resolve())
    except ValueError:
        return f"architecture owner escapes the repository: {reference}"
    if not candidate.exists():
        return f"architecture owner path does not exist: {reference}"
    if separator and not candidate.is_file():
        return f"architecture owner symbol is not in a file: {reference}"
    if separator:
        owner_name = symbol.rsplit("::", 1)[-1]
        owner_src = candidate.read_text(encoding="utf-8", errors="replace")
        if candidate.suffix == ".rs":
            declaration = (
                r"^\s*(?:pub(?:\([^)\n]+\))?\s+)?(?:async\s+)?"
                rf"(?:fn|struct|enum|trait|type|const|static|mod)\s+{re.escape(owner_name)}\b"
            )
        elif candidate.suffix == ".py":
            declaration = rf"^\s*(?:class|def)\s+{re.escape(owner_name)}\b"
        else:
            declaration = rf"\b{re.escape(owner_name)}\b"
        if not re.search(declaration, owner_src, flags=re.MULTILINE):
            return f"architecture owner symbol does not exist: {reference}"
    return None


def architecture_owner_violations(
    src: str, root: pathlib.Path = ROOT
) -> list[str]:
    section = architecture_owner_section(src)
    violations: list[str] = []
    if section is None:
        violations.append(
            f"architecture is missing its enforceable owner section: {ARCHITECTURE_OWNER_HEADING}"
        )
        return violations

    expected = dict(REQUIRED_ARCHITECTURE_OWNERS)
    assigned: dict[str, str] = {}
    for boundary, references in architecture_owner_rows(src):
        if boundary in assigned:
            violations.append(
                f"architecture owner map duplicates boundary row: {boundary}"
            )
            continue
        if boundary not in expected:
            violations.append(
                f"architecture owner map has unrecognized boundary: {boundary}"
            )
        if len(references) != 1:
            violations.append(
                f"architecture owner map must name exactly one owner for {boundary}"
            )
            continue
        assigned[boundary] = references[0]

    for boundary, reference in REQUIRED_ARCHITECTURE_OWNERS:
        actual = assigned.get(boundary)
        if actual is None:
            violations.append(
                f"architecture owner map is missing boundary: {boundary} -> {reference}"
            )
        elif actual != reference:
            violations.append(
                f"architecture owner map assigns {boundary} to {actual}; expected {reference}"
            )

    for reference in sorted(architecture_code_references(src)):
        if violation := owner_reference_violation(reference, root):
            violations.append(violation)
    return violations


def check_architecture_owners(violations: list[str]) -> None:
    violations.extend(architecture_owner_violations(text("docs/src/architecture.md")))


def check_install_fixture_backend_labels(violations: list[str]) -> None:
    fixture = "tests/install/linux/edge_cases.sh"
    src = text(fixture)
    if "gpu-zero-copy" in src:
        fail(violations, f"installer fixture uses retired GPU backend label: {fixture}")


def workflow_requires_competitor_evidence(workflow: str) -> bool:
    """Accept direct CLI wiring or the canonical Make target's exact variable."""
    return (
        "--require-competitors betterleaks,kingfisher" in workflow
        or "REQUIRE_COMPETITORS=betterleaks,kingfisher" in workflow
    )


def check_required_evidence_wiring(violations: list[str]) -> None:
    workflow = text(".github/workflows/differential-bench.yml")
    if "keyhog,betterleaks,kingfisher" not in workflow:
        fail(
            violations,
            "differential-bench workflow missing required evidence: keyhog,betterleaks,kingfisher",
        )
    if not workflow_requires_competitor_evidence(workflow):
        fail(
            violations,
            "differential-bench workflow missing required BetterLeaks and Kingfisher evidence",
        )

    makefile = text("benchmarks/Makefile")
    for required in [
        "GATE_SCANNERS    ?= keyhog,betterleaks,kingfisher",
        "REQUIRE_COMPETITORS ?= betterleaks,kingfisher",
        "cross-device-gate:",
        "--dominance-gate --factor 10",
        "--required-oses linux,macos,windows",
    ]:
        if required not in makefile:
            fail(violations, f"benchmarks/Makefile missing organization gate wiring: {required}")


def check_complexity_budget(violations: list[str]) -> None:
    script = ROOT / "scripts" / "gates" / "complexity_budget.py"
    result = subprocess.run(
        [sys.executable, str(script)],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    if result.returncode != 0:
        fail(violations, "complexity budget gate failed:\n" + result.stdout.rstrip())


def main() -> int:
    violations: list[str] = []
    check_no_generated_cache_clutter(violations)
    check_no_loc_cap_bloat(violations)
    check_current_claims(violations)
    check_architecture_owners(violations)
    check_install_fixture_backend_labels(violations)
    check_required_evidence_wiring(violations)
    check_complexity_budget(violations)

    if violations:
        print("organization audit failed:", file=sys.stderr)
        for item in violations:
            print(f"  - {item}", file=sys.stderr)
        return 1
    print("organization audit passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
