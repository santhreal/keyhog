#!/usr/bin/env python3
"""Validate the prerelease structure of crate changelogs."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


_VERSION_HEADING = re.compile(
    r"^## \d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?: - \d{4}-\d{2}-\d{2})?$"
)
_PLACEHOLDER_BULLET = re.compile(
    r"^-\s*(?:tbd|todo|none|nothing yet|coming soon|no(?: user-facing)? changes(?: yet)?)\.?$",
    re.IGNORECASE,
)


class ChangelogStructureError(ValueError):
    """A crate changelog cannot safely become the next release section."""


def validate_changelog(path: Path, *, allow_released: bool = False) -> None:
    """Require substantive notes in either the pending or just-released section."""
    lines = path.read_text(encoding="utf-8").splitlines()
    matches = [index for index, line in enumerate(lines) if line == "## Unreleased"]
    headings = [
        (index, line) for index, line in enumerate(lines) if line.startswith("## ")
    ]
    if not matches and allow_released:
        if not headings or _VERSION_HEADING.fullmatch(headings[0][1]) is None:
            raise ChangelogStructureError(
                f"{path}: released changelog must begin with a version section"
            )
        section_end = headings[1][0] if len(headings) > 1 else len(lines)
        bullets = [
            line.strip()
            for line in lines[headings[0][0] + 1 : section_end]
            if line.startswith("- ")
        ]
        if not bullets or all(_PLACEHOLDER_BULLET.fullmatch(line) for line in bullets):
            raise ChangelogStructureError(
                f"{path}: newest released section needs a non-placeholder change entry"
            )
        return
    if len(matches) != 1:
        raise ChangelogStructureError(
            f"{path}: expected exactly one '## Unreleased' section; found {len(matches)}"
        )

    unreleased = matches[0]
    if not headings or headings[0] != (unreleased, "## Unreleased"):
        raise ChangelogStructureError(
            f"{path}: '## Unreleased' must precede the newest version section"
        )
    if len(headings) < 2 or _VERSION_HEADING.fullmatch(headings[1][1]) is None:
        raise ChangelogStructureError(
            f"{path}: '## Unreleased' must be immediately followed by a version section"
        )

    bullets = [
        line.strip()
        for line in lines[unreleased + 1 : headings[1][0]]
        if line.startswith("- ")
    ]
    if not bullets or all(_PLACEHOLDER_BULLET.fullmatch(line) for line in bullets):
        raise ChangelogStructureError(
            f"{path}: Unreleased section needs at least one non-placeholder owned change entry"
        )


def validate_changelogs(
    paths: list[Path], *, allow_released: bool = False
) -> list[str]:
    """Return every structural failure so prerelease can report them together."""
    failures = []
    for path in paths:
        try:
            validate_changelog(path, allow_released=allow_released)
        except (ChangelogStructureError, OSError, UnicodeError) as error:
            failures.append(str(error))
    return failures


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("changelogs", nargs="+", type=Path)
    parser.add_argument(
        "--allow-released",
        action="store_true",
        help="accept a substantive newest version section after the release bump",
    )
    args = parser.parse_args(argv)
    failures = validate_changelogs(
        args.changelogs, allow_released=args.allow_released
    )
    if failures:
        print("\n".join(failures), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
