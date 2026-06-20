#!/usr/bin/env python3
"""Cheap organization audit for known KeyHog rot classes.

This is not a style gate. It rejects structural lies that previously made the
repo look healthier than it was: generated LOC-cap tests, stale current docs for
removed surfaces, unproven autoroute wording, and CI/Make targets that omit the
required competitor evidence.
"""

from __future__ import annotations

import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent

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
    return path.relative_to(ROOT).as_posix()


def text(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def fail(violations: list[str], msg: str) -> None:
    violations.append(msg)


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
        "line cap",
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
        for pattern, reason in stale_patterns.items():
            if pattern == r"\bgpu-zero-copy\b" and rel_path == "crates/scanner/src/hw_probe/select.rs":
                continue
            if re.search(pattern, src, flags=re.IGNORECASE):
                fail(violations, f"{reason}: {rel_path}")


def check_install_fixture_backend_labels(violations: list[str]) -> None:
    fixture = "tests/install/linux/edge_cases.sh"
    src = text(fixture)
    if "gpu-zero-copy" in src:
        fail(violations, f"installer fixture uses retired GPU backend label: {fixture}")


def check_required_evidence_wiring(violations: list[str]) -> None:
    workflow = text(".github/workflows/differential-bench.yml")
    for required in [
        "keyhog,betterleaks,kingfisher",
        "--require-competitors betterleaks,kingfisher",
    ]:
        if required not in workflow:
            fail(violations, f"differential-bench workflow missing required evidence: {required}")

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
