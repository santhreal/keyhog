"""Behavioral regressions for changelog-backed GitHub release notes."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from scripts.release_notes import ReleaseNotesError, extract_release_notes


class ReleaseNotesTests(unittest.TestCase):
    """Prove every published body comes from one substantive version section."""

    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.changelog = Path(self.tempdir.name) / "CHANGELOG.md"

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def write(self, body: str) -> None:
        self.changelog.write_text(body, encoding="utf-8")

    def test_extracts_only_requested_version_section(self) -> None:
        """Locks out publishing another version's changes or the whole changelog."""
        self.write(
            "# Changelog\n\n"
            "## [0.5.45] - 2026-07-25\n\n"
            "### Fixed\n\n- Published exact notes.\n\n"
            "## [0.5.44] - 2026-07-24\n\n"
            "### Fixed\n\n- Older change.\n"
        )

        notes = extract_release_notes(self.changelog, "v0.5.45")

        self.assertEqual(notes, "### Fixed\n\n- Published exact notes.\n")
        self.assertNotIn("Older change", notes)

    def test_prerelease_version_is_extracted_exactly(self) -> None:
        """Locks out collapsing an rc tag into the stable version's release notes."""
        self.write(
            "# Changelog\n\n"
            "## [0.6.0-rc.1] - 2026-07-25\n\n"
            "### Added\n\n- Release candidate path.\n"
        )

        self.assertEqual(
            extract_release_notes(self.changelog, "v0.6.0-rc.1"),
            "### Added\n\n- Release candidate path.\n",
        )

    def test_missing_version_fails_closed(self) -> None:
        """Locks out a tag whose release body would otherwise become a placeholder."""
        self.write("# Changelog\n\n## [0.5.44]\n\n### Fixed\n\n- Old.\n")

        with self.assertRaisesRegex(ReleaseNotesError, "found 0"):
            extract_release_notes(self.changelog, "v0.5.45")

    def test_duplicate_version_headings_fail_closed(self) -> None:
        """Locks out choosing an arbitrary section when changelog history is ambiguous."""
        self.write(
            "# Changelog\n\n"
            "## [0.5.45]\n\n### Fixed\n\n- First.\n\n"
            "## [0.5.45] - 2026-07-25\n\n### Fixed\n\n- Second.\n"
        )

        with self.assertRaisesRegex(ReleaseNotesError, "found 2"):
            extract_release_notes(self.changelog, "v0.5.45")

    def test_empty_or_uncategorized_section_fails_closed(self) -> None:
        """Locks out green prerelease checks for headings with no usable notes."""
        for section in ("", "- Change without a Keep a Changelog category.\n"):
            with self.subTest(section=section):
                self.write(f"# Changelog\n\n## [0.5.45]\n\n{section}")
                with self.assertRaises(ReleaseNotesError):
                    extract_release_notes(self.changelog, "v0.5.45")

    def test_placeholder_pointer_fails_even_with_valid_shape(self) -> None:
        """Locks out restoring the old 'See CHANGELOG.md' release body."""
        self.write(
            "# Changelog\n\n"
            "## [0.5.45]\n\n"
            "### Fixed\n\n- See CHANGELOG.md for details.\n"
        )

        with self.assertRaisesRegex(ReleaseNotesError, "placeholder"):
            extract_release_notes(self.changelog, "v0.5.45")

    def test_fenced_fake_heading_does_not_split_release(self) -> None:
        """Locks out Markdown examples truncating the real release body."""
        self.write(
            "# Changelog\n\n"
            "## [0.5.45]\n\n"
            "### Fixed\n\n- Parser remains fence-aware.\n\n"
            "```markdown\n## [0.5.44]\n```\n\n"
            "- Content after the example remains included.\n\n"
            "## [0.5.43]\n\n### Fixed\n\n- Older.\n"
        )

        notes = extract_release_notes(self.changelog, "v0.5.45")

        self.assertIn("## [0.5.44]", notes)
        self.assertIn("Content after the example remains included.", notes)
        self.assertNotIn("- Older.", notes)

    def test_fenced_category_and_bullet_do_not_make_notes_substantive(self) -> None:
        """Locks out a code example satisfying the real changelog-note contract."""
        self.write(
            "# Changelog\n\n"
            "## [0.5.45]\n\n"
            "```markdown\n### Fixed\n\n- Example-only change.\n```\n"
        )

        with self.assertRaisesRegex(ReleaseNotesError, "need an Added"):
            extract_release_notes(self.changelog, "v0.5.45")

    def test_fenced_placeholder_does_not_reject_real_notes(self) -> None:
        """Locks out treating a quoted legacy example as the published prose."""
        self.write(
            "# Changelog\n\n"
            "## [0.5.45]\n\n"
            "### Fixed\n\n- Publish concrete notes.\n\n"
            "```text\nSee CHANGELOG.md\n```\n"
        )

        notes = extract_release_notes(self.changelog, "v0.5.45")

        self.assertIn("- Publish concrete notes.", notes)


if __name__ == "__main__":
    unittest.main()
