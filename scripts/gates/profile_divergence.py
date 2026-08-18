#!/usr/bin/env python3
"""Profile divergence gate.

Parses workspace Cargo.toml at runtime and classifies all keys in [profile.*]
tables into a strict taxonomy:
- SEMANTIC: runtime execution or safety semantics (e.g. panic, overflow-checks, debug-assertions).
  These must adhere to required contracts (e.g. panic = "unwind", overflow-checks = true in release).
- COSMETIC_PERF: compile time, debuginfo, strip, or optimization settings (e.g. opt-level, lto, codegen-units).

Any unclassified key in any profile table fails the gate closed, preventing silent profile divergence.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple

if sys.version_info >= (3, 11):
    import tomllib
else:
    try:
        import tomli as tomllib  # type: ignore
    except ImportError:
        import toml as tomllib  # type: ignore

ROOT = Path(__file__).resolve().parent.parent.parent

# Classified keys taxonomy
SEMANTIC_KEYS: Set[str] = {
    "panic",
    "overflow-checks",
    "debug-assertions",
    "rpath",
}

COSMETIC_PERF_KEYS: Set[str] = {
    "opt-level",
    "lto",
    "codegen-units",
    "strip",
    "debug",
    "incremental",
    "inherits",
    "split-debuginfo",
    "panic-strategy",
}

ALL_KNOWN_KEYS: Set[str] = SEMANTIC_KEYS | COSMETIC_PERF_KEYS


def parse_cargo_profiles(cargo_path: Path) -> Dict[str, Dict[str, Any]]:
    content = cargo_path.read_text(encoding="utf-8")
    data = tomllib.loads(content)
    profiles = data.get("profile", {})
    return profiles


def classify_profile_keys(profiles: Dict[str, Dict[str, Any]]) -> Tuple[List[str], List[str]]:
    """Returns (errors, warnings)."""
    errors: List[str] = []
    warnings: List[str] = []

    if not profiles:
        errors.append("No [profile.*] tables found in Cargo.toml")
        return errors, warnings

    for profile_name, profile_data in sorted(profiles.items()):
        if not isinstance(profile_data, dict):
            continue
        for key, val in sorted(profile_data.items()):
            if key not in ALL_KNOWN_KEYS:
                errors.append(
                    f"Unclassified key in [profile.{profile_name}]: '{key}' = {val!r}. "
                    f"Every profile key must be classified as SEMANTIC or COSMETIC_PERF in profile_divergence.py."
                )

    # Shipped release profile invariants:
    release_profile = profiles.get("release")
    if not release_profile:
        errors.append("Missing required [profile.release] table in Cargo.toml")
    else:
        panic_val = release_profile.get("panic")
        if panic_val != "unwind":
            errors.append(
                f"[profile.release] panic strategy must be 'unwind' (got {panic_val!r}) "
                f"to support catch_unwind isolation boundaries in shipped release binaries."
            )
        overflow_val = release_profile.get("overflow-checks")
        if overflow_val is not True:
            errors.append(
                f"[profile.release] overflow-checks must be true (got {overflow_val!r}) "
                f"to prevent silent arithmetic overflow in release builds."
            )

    return errors, warnings


def run_self_test() -> int:
    """Self-test for the profile divergence classifier."""
    print("Running profile_divergence self-tests...")
    # 1. Valid config
    valid_profiles = {
        "release": {
            "opt-level": 3,
            "lto": "fat",
            "codegen-units": 1,
            "panic": "unwind",
            "strip": "symbols",
            "debug": False,
            "incremental": False,
            "overflow-checks": True,
        },
        "release-fast": {
            "inherits": "release",
            "lto": "thin",
            "codegen-units": 16,
            "strip": "none",
            "debug-assertions": True,
        },
    }
    errors, _ = classify_profile_keys(valid_profiles)
    assert not errors, f"Expected clean validation on valid config, got: {errors}"

    # 2. Unclassified key
    unclassified = {
        "release": {
            "panic": "unwind",
            "overflow-checks": True,
            "unknown-experimental-flag": True,
        }
    }
    errors, _ = classify_profile_keys(unclassified)
    assert any("Unclassified key" in e and "unknown-experimental-flag" in e for e in errors), (
        f"Expected unclassified key error, got: {errors}"
    )

    # 3. Release panic = "abort" mutation
    abort_profile = {
        "release": {
            "panic": "abort",
            "overflow-checks": True,
        }
    }
    errors, _ = classify_profile_keys(abort_profile)
    assert any("panic strategy must be 'unwind'" in e for e in errors), (
        f"Expected panic unwind error, got: {errors}"
    )

    # 4. Release overflow-checks = false mutation
    overflow_profile = {
        "release": {
            "panic": "unwind",
            "overflow-checks": False,
        }
    }
    errors, _ = classify_profile_keys(overflow_profile)
    assert any("overflow-checks must be true" in e for e in errors), (
        f"Expected overflow-checks error, got: {errors}"
    )

    print("All profile_divergence self-tests passed successfully.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Profile divergence gate")
    parser.add_argument("--self-test", action="store_true", help="Run internal self-tests")
    parser.add_argument(
        "--cargo-toml",
        type=Path,
        default=ROOT / "Cargo.toml",
        help="Path to workspace Cargo.toml",
    )
    args = parser.parse_args()

    if args.self_test:
        return run_self_test()

    cargo_path = args.cargo_toml
    if not cargo_path.exists():
        print(f"Error: Cargo.toml not found at {cargo_path}", file=sys.stderr)
        return 1

    profiles = parse_cargo_profiles(cargo_path)
    errors, warnings = classify_profile_keys(profiles)

    for warning in warnings:
        print(f"WARNING: {warning}", file=sys.stderr)

    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1

    print(
        f"Profile divergence gate passed: {len(profiles)} profiles verified against semantic/cosmetic taxonomy."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
