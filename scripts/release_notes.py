#!/usr/bin/env python3
"""Render one version's GitHub release notes from the canonical changelog."""

from __future__ import annotations

import argparse
import re
from pathlib import Path


class ReleaseNotesError(RuntimeError):
    """The requested changelog section cannot become truthful release notes."""


_TAG_RE = re.compile(r"^v(?P<version>\d+\.\d+\.\d+)$")


def _lines_outside_fences(lines: list[str]) -> list[tuple[int, str]]:
    """Return indexed Markdown lines that are not inside fenced code blocks."""
    visible: list[tuple[int, str]] = []
    fence: str | None = None
    for index, line in enumerate(lines):
        stripped = line.lstrip()
        marker = None
        if stripped.startswith("```"):
            marker = "```"
        elif stripped.startswith("~~~"):
            marker = "~~~"
        if marker is not None:
            if fence is None:
                fence = marker
            elif fence == marker:
                fence = None
            continue
        if fence is None:
            visible.append((index, line))
    return visible


def _top_level_headings(lines: list[str]) -> list[tuple[int, str]]:
    """Return Markdown level-two headings outside fenced code blocks."""
    return [
        (index, line)
        for index, line in _lines_outside_fences(lines)
        if line.startswith("## ")
    ]


def validate_release_notes(notes: str, tag: str) -> str:
    """Require concrete changelog entries instead of a changelog pointer."""
    rendered = notes.strip()
    if not rendered:
        raise ReleaseNotesError(f"{tag} changelog section is empty")
    prose = [line for _index, line in _lines_outside_fences(rendered.splitlines())]
    if "see changelog" in "\n".join(prose).casefold():
        raise ReleaseNotesError(
            f"{tag} release notes contain a placeholder changelog pointer"
        )
    if not any(line.startswith("- ") and line[2:].strip() for line in prose):
        raise ReleaseNotesError(f"{tag} release notes need at least one concrete change")
    return rendered + "\n"


def extract_release_notes(changelog: Path, tag: str) -> str:
    """Extract and validate the exact ``## [version]`` changelog section."""
    match = _TAG_RE.fullmatch(tag)
    if match is None:
        raise ReleaseNotesError(
            f"release tag {tag!r} must be exact vMAJOR.MINOR.PATCH semver"
        )
    version = match.group("version")
    lines = changelog.read_text(encoding="utf-8").splitlines()
    heading_re = re.compile(
        rf"^## \[{re.escape(version)}\](?: - \d{{4}}-\d{{2}}-\d{{2}})?$"
    )
    headings = _top_level_headings(lines)
    matches = [
        (position, heading)
        for position, heading in headings
        if heading_re.fullmatch(heading)
    ]
    if len(matches) != 1:
        raise ReleaseNotesError(
            f"CHANGELOG.md must contain exactly one release heading for {tag}; "
            f"found {len(matches)}"
        )
    start = matches[0][0] + 1
    end = next(
        (position for position, _heading in headings if position >= start), len(lines)
    )
    return validate_release_notes("\n".join(lines[start:end]), tag)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Render exact GitHub release notes from CHANGELOG.md."
    )
    parser.add_argument("--tag", required=True)
    parser.add_argument("--changelog", type=Path, default=Path("CHANGELOG.md"))
    parser.add_argument("--output", type=Path)
    return parser


def main() -> int:
    args = _parser().parse_args()
    notes = extract_release_notes(args.changelog, args.tag)
    if args.output is None:
        print(notes, end="")
    else:
        args.output.write_text(notes, encoding="utf-8")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ReleaseNotesError) as error:
        raise SystemExit(f"ERROR: {error}") from error
