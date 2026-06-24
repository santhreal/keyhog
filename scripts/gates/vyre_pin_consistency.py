#!/usr/bin/env python3
"""Gate - VYRE PIN CONSISTENCY.

Keyhog consumes Vyre as five runtime crates from crates.io:
`vyre`, `vyre-libs`, `vyre-driver-wgpu`, `vyre-driver-cuda`, and
`vyre-runtime`.

This gate is intentionally source-only and fast. It prevents the failure modes
that made the old setup brittle:

  1. all five deps exist in root `[workspace.dependencies]`;
  2. all five are exact registry pins at the same version;
  3. none of the five carries a `path =` override;
  4. the repository has no `vendor/` source tree;
  5. no Cargo manifest resolves a dependency through `vendor/`;
  6. no Cargo manifest reintroduces the retired `third_party/vyre` mirror;
  7. the key Vyre docs agree that the active build uses crates.io pins.

Run: python3 scripts/gates/vyre_pin_consistency.py
"""
from __future__ import annotations

import pathlib
import re
import sys
import tomllib

REPO = pathlib.Path(__file__).resolve().parents[2]
ROOT_CARGO = REPO / "Cargo.toml"
REQUIRED_VERSION = "0.6.3"
GENERATED_PARTS = {
    ".git",
    "target",
    "docs/book",
    "benchmarks/corpora",
    "benchmarks/results",
    "benchmarks/results-cross-device",
}

# Logical dep key in [workspace.dependencies] -> published crate name.
VYRE_DEPS: dict[str, str] = {
    "vyre": "vyre",
    "vyre_libs": "vyre-libs",
    "vyre-driver-wgpu": "vyre-driver-wgpu",
    "vyre-driver-cuda": "vyre-driver-cuda",
    "vyre-runtime": "vyre-runtime",
}


def _strip_version_op(v: str) -> str:
    """`=0.6.3` -> `0.6.3`; `0.6.3` -> `0.6.3`."""
    return v.lstrip("=").strip()


def _manifest_version_and_path(
    key: str, pkg: str, spec: object, violations: list[str]
) -> tuple[str | None, str | None]:
    """Return (version, path) for a workspace dependency spec."""
    if isinstance(spec, str):
        if key != pkg:
            violations.append(
                f"vyre dep '{key}' must be a table with package='{pkg}' because "
                f"the dependency key differs from the published crate name."
            )
        return spec, None

    if not isinstance(spec, dict):
        violations.append(
            f"vyre dep '{key}' must be an exact string pin or an inline table, got: {spec!r}"
        )
        return None, None

    declared_pkg = spec.get("package", key)
    if declared_pkg != pkg:
        violations.append(
            f"vyre dep '{key}' resolves to package '{declared_pkg}', expected '{pkg}'."
        )

    version = spec.get("version")
    if not isinstance(version, str):
        violations.append(f"vyre dep '{key}' has no string `version` pin.")
        version = None

    path = spec.get("path")
    if path is not None and not isinstance(path, str):
        violations.append(f"vyre dep '{key}' has non-string `path`: {path!r}.")
        path = None

    return version, path


def _cargo_manifests() -> list[pathlib.Path]:
    manifests: list[pathlib.Path] = []
    for path in REPO.rglob("Cargo.toml"):
        if _is_generated_path(path):
            continue
        manifests.append(path)
    return sorted(manifests)


def _is_generated_path(path: pathlib.Path) -> bool:
    try:
        rel = path.relative_to(REPO).as_posix()
    except ValueError:
        return True
    return any(rel == part or rel.startswith(f"{part}/") for part in GENERATED_PARTS)


def _vendor_dirs() -> list[pathlib.Path]:
    return sorted(
        path
        for path in REPO.rglob("vendor")
        if path.is_dir() and not _is_generated_path(path)
    )


def check() -> list[str]:
    violations: list[str] = []

    raw = ROOT_CARGO.read_text(encoding="utf-8")
    data = tomllib.loads(raw)

    ws = data.get("workspace", {})
    deps = ws.get("dependencies", {})

    vendor_dirs = _vendor_dirs()
    if vendor_dirs:
        found = ", ".join(path.relative_to(REPO).as_posix() for path in vendor_dirs)
        violations.append(
            f"vendor/ source tree must not exist (found: {found}). Keyhog consumes "
            "Vyre from crates.io pins and must not carry vendored source snapshots."
        )

    exclude = ws.get("exclude", [])
    if any(isinstance(entry, str) and entry.startswith("vendor/") for entry in exclude):
        violations.append(
            "root Cargo.toml [workspace] exclude still lists vendor paths. "
            "There must be no repository vendor tree to exclude."
        )

    versions: dict[str, str] = {}
    for key, pkg in VYRE_DEPS.items():
        if key not in deps:
            violations.append(
                f"root [workspace.dependencies] is missing vyre dep '{key}' "
                f"(package '{pkg}')."
            )
            continue

        version, path = _manifest_version_and_path(key, pkg, deps[key], violations)
        if version is not None:
            if not version.startswith("="):
                violations.append(
                    f"vyre dep '{key}' version '{version}' is not an exact pin "
                    "(must be `=X.Y.Z`)."
                )
            clean = _strip_version_op(version)
            versions[key] = clean
            if clean != REQUIRED_VERSION:
                violations.append(
                    f"vyre dep '{key}' pins '{version}', expected '={REQUIRED_VERSION}'."
                )

        if path is not None:
            violations.append(
                f"vyre dep '{key}' still has path override '{path}'. Keyhog must "
                "consume Vyre from crates.io exact pins only."
            )

    distinct = set(versions.values())
    if len(distinct) > 1:
        violations.append(
            "vyre pins are not in lockstep: "
            + ", ".join(f"{k}={v}" for k, v in sorted(versions.items()))
        )

    vendor_path_re = re.compile(r'path\s*=\s*"[^"]*vendor/[^"]*"')
    retired_mirror_re = re.compile(r'path\s*=\s*"[^"]*third_party/vyre[^"]*"')
    live_tree_re = re.compile(r'path\s*=\s*"[^"]*libs/performance/matching/vyre[^"]*"')
    for cargo in _cargo_manifests():
        rel = cargo.relative_to(REPO).as_posix()
        text = cargo.read_text(encoding="utf-8")
        if vendor_path_re.search(text):
            violations.append(
                f"{rel} declares a Cargo path dependency into vendor/. Keyhog "
                "must not resolve dependencies from repository vendored snapshots."
            )
        if retired_mirror_re.search(text):
            violations.append(
                f"{rel} declares a Cargo path dependency into retired third_party/vyre. "
                f"Use the crates.io `={REQUIRED_VERSION}` Vyre pins."
            )
        if live_tree_re.search(text):
            violations.append(
                f"{rel} declares a Cargo path dependency into the Santh live Vyre tree. "
                "That breaks source ships on hosts without the mounted share."
            )

    stale_doc_claims: list[tuple[str, str, str]] = [
        (
            "PUBLISHING.md",
            "third_party/vyre",
            "PUBLISHING.md still describes the retired third_party/vyre mirror.",
        ),
        (
            "PUBLISHING.md",
            "path override",
            "PUBLISHING.md still describes Vyre path overrides as active.",
        ),
        (
            "docs/vyre-usage.md",
            "third_party/vyre",
            "docs/vyre-usage.md still describes the retired third_party/vyre mirror.",
        ),
        (
            "docs/vyre-usage.md",
            "not in any published",
            "docs/vyre-usage.md still claims the required Vyre API is unpublished.",
        ),
        (
            "docs/CROSS_OS_STATUS.md",
            "third_party/vyre",
            "docs/CROSS_OS_STATUS.md still describes the retired third_party/vyre mirror.",
        ),
    ]
    for relpath, needle, msg in stale_doc_claims:
        file = REPO / relpath
        if file.is_file() and needle in file.read_text(encoding="utf-8"):
            violations.append(f"{msg} [{relpath}]")

    return violations


def main() -> int:
    violations = check()
    if violations:
        print("VYRE PIN CONSISTENCY GATE FAILED:", file=sys.stderr)
        for violation in violations:
            print(f"  - {violation}", file=sys.stderr)
        return 1
    print(
        "vyre pin consistency gate passed "
        f"(5 crates, lockstep registry pins at ={REQUIRED_VERSION}, no path overrides)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
