#!/usr/bin/env python3
"""Gate - VYRE PIN CONSISTENCY.

KeyHog consumes VYRE as six runtime crates from one authenticated Git revision:
`vyre`, `vyre-libs`, `vyre-driver-wgpu`, `vyre-driver-cuda`,
`vyre-driver-metal`, and `vyre-runtime`.

This gate is intentionally source-only and fast. It prevents split VYRE graphs:

  1. all six dependencies exist in root `[workspace.dependencies]`;
  2. all six use the same exact package version;
  3. all six use the canonical repository and immutable revision;
  4. none carries a `path =` override;
  5. the repository has no `vendor/` source tree;
  6. no Cargo manifest resolves a dependency through `vendor/`;
  7. no Cargo manifest reintroduces the retired `third_party/vyre` mirror;
  8. the key VYRE docs do not claim a retired source layout.

Run: python3 scripts/gates/vyre_pin_consistency.py
"""
from __future__ import annotations

import pathlib
import re
import sys
import tomllib

REPO = pathlib.Path(__file__).resolve().parents[2]
ROOT_CARGO = REPO / "Cargo.toml"
REQUIRED_VERSION = "0.7.2"
REQUIRED_GIT = "https://github.com/santhreal/vyre.git"
REQUIRED_REV = "8be30afe43fb54e38965dd9e9ae46a1b39b824a2"

# Logical dep key in [workspace.dependencies] -> published crate name.
VYRE_DEPS: dict[str, str] = {
    "vyre": "vyre",
    "vyre_libs": "vyre-libs",
    "vyre-driver-wgpu": "vyre-driver-wgpu",
    "vyre-driver-cuda": "vyre-driver-cuda",
    "vyre-driver-metal": "vyre-driver-metal",
    "vyre-runtime": "vyre-runtime",
}


def _strip_version_op(v: str) -> str:
    """`=0.7.2` -> `0.7.2`; `0.7.2` -> `0.7.2`."""
    return v.lstrip("=").strip()


def _manifest_identity(
    key: str, pkg: str, spec: object, violations: list[str]
) -> tuple[str | None, str | None, str | None, str | None]:
    """Return (version, path, git, rev) for a workspace dependency spec."""
    if isinstance(spec, str):
        if key != pkg:
            violations.append(
                f"vyre dep '{key}' must be a table with package='{pkg}' because "
                f"the dependency key differs from the published crate name."
            )
        return spec, None, None, None

    if not isinstance(spec, dict):
        violations.append(
            f"vyre dep '{key}' must be an exact string pin or an inline table, got: {spec!r}"
        )
        return None, None, None, None

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

    git = spec.get("git")
    if git is not None and not isinstance(git, str):
        violations.append(f"vyre dep '{key}' has non-string `git`: {git!r}.")
        git = None

    rev = spec.get("rev")
    if rev is not None and not isinstance(rev, str):
        violations.append(f"vyre dep '{key}' has non-string `rev`: {rev!r}.")
        rev = None

    return version, path, git, rev


def _cargo_manifests() -> list[pathlib.Path]:
    manifests: list[pathlib.Path] = []
    for path in REPO.rglob("Cargo.toml"):
        if _is_generated_path(path):
            continue
        manifests.append(path)
    return sorted(manifests)


def _is_generated_path(path: pathlib.Path) -> bool:
    try:
        parts = path.relative_to(REPO).parts
    except ValueError:
        return True
    return (
        parts[:1] in {(".git",), ("target",)}
        or parts[:2] == ("docs", "book")
        or (
            len(parts) >= 2
            and parts[0] == "benchmarks"
            and (parts[1] == "corpora" or parts[1].startswith("results"))
        )
    )


def _vendor_dirs() -> list[pathlib.Path]:
    return sorted(
        path
        for path in REPO.rglob("vendor")
        if path.is_dir() and not _is_generated_path(path)
    )


def _path_has_component(value: str, component: str) -> bool:
    parts = [part for part in value.replace("\\", "/").split("/") if part]
    return component in parts


def _manifest_path_values(text: str) -> list[str]:
    values: list[str] = []
    for line in text.splitlines():
        stripped = line.lstrip()
        if stripped.startswith("#"):
            continue
        match = re.match(r"""^\s*path\s*=\s*["']([^"']+)["']""", line)
        if match:
            values.append(match.group(1))
    return values


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
            f"vendor/ source tree must not exist (found: {found}). KeyHog consumes "
            "VYRE from crates.io pins and must not carry vendored source snapshots."
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

        version, path, git, rev = _manifest_identity(key, pkg, deps[key], violations)
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
                f"vyre dep '{key}' still has path override '{path}'. KeyHog must "
                "consume VYRE from crates.io exact pins only."
            )

        if git != REQUIRED_GIT:
            violations.append(
                f"vyre dep '{key}' uses git source {git!r}, expected {REQUIRED_GIT!r}."
            )
        if rev != REQUIRED_REV:
            violations.append(
                f"vyre dep '{key}' pins revision {rev!r}, expected {REQUIRED_REV!r}."
            )

    for dep_key in deps:
        if dep_key.startswith("vyre") and dep_key not in VYRE_DEPS:
            violations.append(
                f"unbudgeted vyre dependency '{dep_key}' in root [workspace.dependencies]"
            )

    distinct = set(versions.values())
    if len(distinct) > 1:
        violations.append(
            "vyre pins are not in lockstep: "
            + ", ".join(f"{k}={v}" for k, v in sorted(versions.items()))
        )
    for cargo in _cargo_manifests():
        rel = cargo.relative_to(REPO).as_posix()
        text = cargo.read_text(encoding="utf-8")
        path_values = [value.replace("\\", "/") for value in _manifest_path_values(text)]
        if any(_path_has_component(value, "vendor") for value in path_values):
            violations.append(
                f"{rel} declares a Cargo path dependency into vendor/. KeyHog "
                "must not resolve dependencies from repository vendored snapshots."
            )
        if any("third_party/vyre" in value for value in path_values):
            violations.append(
                f"{rel} declares a Cargo path dependency into retired third_party/vyre. "
                f"Use the crates.io `={REQUIRED_VERSION}` VYRE pins."
            )
        if any("libs/performance/matching/vyre" in value for value in path_values):
            violations.append(
                f"{rel} declares a Cargo path dependency into the Santh live VYRE tree. "
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
            "PUBLISHING.md still describes VYRE path overrides as active.",
        ),
        (
            "docs/src/reference/vyre-integration.md",
            "third_party/vyre",
            "VYRE integration reference still describes the retired third_party/vyre mirror.",
        ),
        (
            "docs/src/reference/vyre-integration.md",
            "not in any published",
            "VYRE integration reference still claims the required VYRE API is unpublished.",
        ),
    ]
    for relpath, needle, msg in stale_doc_claims:
        file = REPO / relpath
        if not file.is_file():
            violations.append(
                f"required document for stale claim check does not exist: {relpath}"
            )
            continue
        if needle in file.read_text(encoding="utf-8"):
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
        f"({len(VYRE_DEPS)} crates, ={REQUIRED_VERSION}, revision {REQUIRED_REV}, "
        "no path overrides)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
