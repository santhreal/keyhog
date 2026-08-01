#!/usr/bin/env python3
"""Prepare the next patch release from one successful main-branch push."""

from __future__ import annotations

import argparse
import datetime as dt
import re
import tomllib
from pathlib import Path

try:
    from scripts.prepare_release import PrepareError, parse_version, prepare
except ModuleNotFoundError:
    from prepare_release import PrepareError, parse_version, prepare


class AutoReleaseError(ValueError):
    """The successful CI revision cannot become an automatic release."""


def workspace_version(root: Path) -> str:
    """Read the canonical workspace package version."""
    try:
        value = tomllib.loads((root / "Cargo.toml").read_text(encoding="utf-8"))[
            "workspace"
        ]["package"]["version"]
    except (OSError, KeyError, tomllib.TOMLDecodeError) as error:
        raise AutoReleaseError(f"cannot read workspace version: {error}") from error
    if not isinstance(value, str):
        raise AutoReleaseError("workspace package version must be a string")
    parse_version(value)
    return value


def next_patch_version(current: str) -> str:
    """Increment only the patch component of canonical stable SemVer."""
    major, minor, patch = parse_version(current)
    return f"{major}.{minor}.{patch + 1}"


def release_summary(value: str) -> str:
    """Normalize one commit subject into a changelog sentence."""
    summary = re.sub(r"\s+", " ", value).strip().lstrip("-").strip()
    if not summary:
        raise AutoReleaseError("release summary must contain text")
    if len(summary) > 240:
        raise AutoReleaseError("release summary must be at most 240 characters")
    if summary[-1] not in ".!?)`":
        summary += "."
    return summary


def prepare_next_release(
    root: Path, summary: str, release_date: str, apply: bool
) -> tuple[str, list[Path]]:
    """Prepare one patch release and return its version and changed paths."""
    version = next_patch_version(workspace_version(root))
    normalized = release_summary(summary)
    try:
        changed = prepare(root, version, release_date, apply, normalized)
    except PrepareError as error:
        raise AutoReleaseError(str(error)) from error
    return version, changed


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Prepare the next patch release after successful CI."
    )
    parser.add_argument("--summary", required=True, help="successful push commit subject")
    parser.add_argument("--date", default=dt.datetime.now(dt.UTC).date().isoformat())
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--apply", action="store_true", help="write the release transaction")
    args = parser.parse_args()
    try:
        version, changed = prepare_next_release(
            args.root.resolve(), args.summary, args.date, args.apply
        )
    except (OSError, AutoReleaseError) as error:
        parser.error(str(error))
    mode = "prepared" if args.apply else "validated"
    print(f"{version}\t{mode}\t{len(changed)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
