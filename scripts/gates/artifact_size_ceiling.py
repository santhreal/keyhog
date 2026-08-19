#!/usr/bin/env python3
"""Artifact size ceiling and release profile stripping gate (Row 49, 51, 97).

Validates that:
1. Workspace Cargo.toml release profiles enforce `strip = "symbols"` (or `strip = true`)
   and `panic = "unwind"` for degradation contracts.
2. Binary size ceilings per platform are recorded and enforced when release artifacts exist.
"""

from __future__ import annotations

import os
import pathlib
import sys
if sys.version_info >= (3, 11):
    import tomllib
else:
    try:
        import tomli as tomllib  # type: ignore
    except ImportError:
        import toml as tomllib  # type: ignore

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
CARGO_TOML = REPO_ROOT / "Cargo.toml"

# Size ceilings in bytes per target platform (stripped release binaries)
PLATFORM_SIZE_CEILINGS: dict[str, int] = {
    "linux-x86_64": 35 * 1024 * 1024,   # 35 MB
    "linux-aarch64": 35 * 1024 * 1024,  # 35 MB
    "macos-x86_64": 35 * 1024 * 1024,   # 35 MB
    "macos-arm64": 35 * 1024 * 1024,    # 35 MB
    "windows-x86_64": 40 * 1024 * 1024, # 40 MB
}


def check_cargo_profiles(cargo_path: pathlib.Path) -> None:
    text = cargo_path.read_text(encoding="utf-8")
    data = tomllib.loads(text)
    profile = data.get("profile", {})
    release = profile.get("release", {})

    strip_val = release.get("strip")
    if strip_val not in ("symbols", True):
        raise ValueError(
            f"Cargo.toml [profile.release] must specify `strip = \"symbols\"` (got {strip_val!r})"
        )

    panic_val = release.get("panic")
    if panic_val != "unwind":
        raise ValueError(
            f"Cargo.toml [profile.release] must specify `panic = \"unwind\"` (got {panic_val!r})"
        )


def check_binary_sizes() -> None:
    # Check stripped release binary locations if present
    target_dirs = [
        REPO_ROOT / "target" / "release",
        pathlib.Path("/mnt/FlareTraining/santh-archive/cargo-target/release"),
    ]

    current_platform = "linux-x86_64"
    ceiling = PLATFORM_SIZE_CEILINGS[current_platform]

    for d in target_dirs:
        bin_path = d / "keyhog"
        if bin_path.is_file():
            size = bin_path.stat().st_size
            if size > ceiling:
                raise ValueError(
                    f"Release binary at {bin_path} exceeds size ceiling for {current_platform}: "
                    f"{size} bytes > {ceiling} bytes"
                )


def self_test() -> int:
    check_cargo_profiles(CARGO_TOML)
    check_binary_sizes()
    return 0


def main(argv: list[str]) -> int:
    try:
        check_cargo_profiles(CARGO_TOML)
        check_binary_sizes()
        print("Artifact size ceiling gate passed: release profiles and platform ceilings verified.")
        return 0
    except Exception as e:
        print(f"Artifact size ceiling gate failed: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
