#!/usr/bin/env python3
"""Update canonical documentation version pins without rewriting measured evidence."""

from __future__ import annotations

import argparse
import os
import re
from pathlib import Path

BENCH_MARKER = re.compile(r"^<!-- BENCH:[^:]+:(start|end) -->$")


class VersionBumpError(ValueError):
    """The documentation cannot be updated without losing provenance."""


def bump_markdown(text: str, current: str, next_version: str) -> str:
    """Replace the current version outside generated benchmark sections."""
    current_pattern = re.compile(
        rf"(?<![0-9])(?P<prefix>v?){re.escape(current)}(?![0-9])"
    )
    inside_benchmark = False
    replacements = 0
    output: list[str] = []

    for line in text.splitlines(keepends=True):
        marker = BENCH_MARKER.match(line.rstrip("\r\n"))
        if marker:
            boundary = marker.group(1)
            if boundary == "start":
                if inside_benchmark:
                    raise VersionBumpError("nested benchmark start marker")
                inside_benchmark = True
            elif not inside_benchmark:
                raise VersionBumpError("benchmark end marker without a start marker")
            else:
                inside_benchmark = False
            output.append(line)
            continue

        if not inside_benchmark:
            line, line_replacements = current_pattern.subn(
                lambda match: f"{match.group('prefix')}{next_version}", line
            )
            replacements += line_replacements
        output.append(line)

    if inside_benchmark:
        raise VersionBumpError("benchmark start marker without an end marker")
    if replacements == 0:
        raise VersionBumpError(f"document does not contain canonical pin {current}")

    updated = "".join(output)
    outside = _outside_benchmark_text(updated)
    if current_pattern.search(outside):
        raise VersionBumpError(f"canonical version {current} remains outside benchmark evidence")
    return updated


def _outside_benchmark_text(text: str) -> str:
    """Return only operator-maintained text, validating benchmark markers."""
    inside_benchmark = False
    output: list[str] = []
    for line in text.splitlines(keepends=True):
        marker = BENCH_MARKER.match(line.rstrip("\r\n"))
        if marker:
            boundary = marker.group(1)
            if boundary == "start":
                if inside_benchmark:
                    raise VersionBumpError("nested benchmark start marker")
                inside_benchmark = True
            elif not inside_benchmark:
                raise VersionBumpError("benchmark end marker without a start marker")
            else:
                inside_benchmark = False
            continue
        if not inside_benchmark:
            output.append(line)
    if inside_benchmark:
        raise VersionBumpError("benchmark start marker without an end marker")
    return "".join(output)


def bump_file(path: Path, current: str, next_version: str) -> None:
    """Atomically update one documentation file while preserving its mode."""
    updated = bump_markdown(path.read_text(), current, next_version)
    temporary = path.with_name(path.name + ".version-bump-tmp")
    temporary.write_text(updated)
    os.chmod(temporary, path.stat().st_mode)
    os.replace(temporary, path)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--current", required=True)
    parser.add_argument("--next", dest="next_version", required=True)
    parser.add_argument("paths", nargs="+", type=Path)
    args = parser.parse_args()

    for path in args.paths:
        try:
            bump_file(path, args.current, args.next_version)
        except (OSError, VersionBumpError) as error:
            parser.error(f"{path}: {error}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
