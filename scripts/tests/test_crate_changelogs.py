"""Focused regressions for the crate prerelease changelog gate."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from scripts.gates.crate_changelogs import (
    ChangelogStructureError,
    validate_changelog,
)


class CrateChangelogTests(unittest.TestCase):
    """Lock the exact Unreleased section accepted by prerelease."""

    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.changelog = Path(self.tempdir.name) / "CHANGELOG.md"

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def write(self, body: str) -> None:
        self.changelog.write_text(body, encoding="utf-8")

    def test_accepts_one_substantive_unreleased_section_before_newest(self) -> None:
        self.write(
            "# Changelog\n\n"
            "## Unreleased\n\n"
            "- Return typed scanner errors to library callers.\n\n"
            "## 0.5.45 - 2026-07-22\n\n"
            "- Published behavior.\n\n"
            "## 0.5.44 - 2026-07-21\n\n"
            "- Older behavior.\n"
        )

        validate_changelog(self.changelog)

    def test_released_mode_accepts_substantive_newest_version(self) -> None:
        """The always-run gate must accept the exact changelog state after a version bump."""
        self.write(
            "# Changelog\n\n"
            "## 0.5.46 - 2026-07-25\n\n"
            "- Return typed scanner errors to library callers.\n\n"
            "## 0.5.45 - 2026-07-22\n\n"
            "- Published behavior.\n"
        )

        validate_changelog(self.changelog, allow_released=True)

    def test_prerelease_mode_still_rejects_missing_unreleased_section(self) -> None:
        """The bump preflight must not accept already-cut notes as pending release notes."""
        self.write(
            "# Changelog\n\n"
            "## 0.5.46 - 2026-07-25\n\n"
            "- Published behavior.\n"
        )

        with self.assertRaisesRegex(ChangelogStructureError, "exactly one"):
            validate_changelog(self.changelog)

    def test_released_mode_rejects_empty_newest_version(self) -> None:
        """A version heading without owned changes must never satisfy the release gate."""
        self.write(
            "# Changelog\n\n"
            "## 0.5.46 - 2026-07-25\n\n"
            "## 0.5.45 - 2026-07-22\n\n"
            "- Published behavior.\n"
        )

        with self.assertRaisesRegex(ChangelogStructureError, "non-placeholder"):
            validate_changelog(self.changelog, allow_released=True)

    def test_rejects_duplicate_unreleased_sections(self) -> None:
        self.write(
            "# Changelog\n\n"
            "## Unreleased\n\n- First change.\n\n"
            "## Unreleased\n\n- Second change.\n\n"
            "## 0.5.45 - 2026-07-22\n\n- Published behavior.\n"
        )

        with self.assertRaisesRegex(ChangelogStructureError, "exactly one"):
            validate_changelog(self.changelog)

    def test_rejects_unreleased_after_a_version_section(self) -> None:
        self.write(
            "# Changelog\n\n"
            "## 0.5.45 - 2026-07-22\n\n- Published behavior.\n\n"
            "## Unreleased\n\n- Late change.\n\n"
            "## 0.5.44 - 2026-07-21\n\n- Older behavior.\n"
        )

        with self.assertRaisesRegex(ChangelogStructureError, "must precede"):
            validate_changelog(self.changelog)

    def test_rejects_empty_or_placeholder_unreleased_sections(self) -> None:
        for section in ("", "- No changes.\n"):
            with self.subTest(section=section):
                self.write(
                    "# Changelog\n\n"
                    f"## Unreleased\n\n{section}\n"
                    "## 0.5.45 - 2026-07-22\n\n- Published behavior.\n"
                )
                with self.assertRaisesRegex(
                    ChangelogStructureError, "non-placeholder"
                ):
                    validate_changelog(self.changelog)


if __name__ == "__main__":
    unittest.main()
