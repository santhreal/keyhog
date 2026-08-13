"""Contracts for the changelog-to-GitHub-release notes renderer.

WHY: a release entry that says "see the changelog" or carries an empty section
is indistinguishable from a release that shipped nothing. The renderer is the
only gate between the generated changelog and the published release body, so it
must refuse a section it cannot prove carries concrete entries. It does not
check that the entries are accurate; only a human writes those.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from scripts.release_notes import ReleaseNotesError, extract_release_notes


def _changelog(body: str) -> Path:
    directory = Path(tempfile.mkdtemp())
    path = directory / "CHANGELOG.md"
    path.write_text(body, encoding="utf-8")
    return path


HEADER = "# Changelog\n\nAll notable changes to KeyHog.\n\n"


class ExtractReleaseNotesTests(unittest.TestCase):
    def test_extracts_only_the_requested_version_section(self) -> None:
        path = _changelog(
            HEADER
            + "## [0.5.71] - 2026-08-13\n\n### Changed\n\n- Newer entry.\n\n"
            "## [0.5.70] - 2026-08-12\n\n- Older entry.\n"
        )
        notes = extract_release_notes(path, "v0.5.71")
        self.assertIn("- Newer entry.", notes)
        self.assertNotIn("Older entry", notes)
        self.assertNotIn("## [0.5.70]", notes)
        self.assertTrue(notes.endswith("\n"))

    def test_accepts_a_generated_section_without_category_headings(self) -> None:
        path = _changelog(HEADER + "## [0.5.71] - 2026-08-13\n\n- Bare entry.\n")
        self.assertEqual(extract_release_notes(path, "v0.5.71"), "- Bare entry.\n")

    def test_last_section_runs_to_end_of_file(self) -> None:
        path = _changelog(HEADER + "## [0.1.0] - 2026-01-01\n\n- First release.\n")
        self.assertEqual(extract_release_notes(path, "v0.1.0"), "- First release.\n")

    def test_heading_without_a_date_still_resolves(self) -> None:
        path = _changelog(HEADER + "## [0.5.71]\n\n- Undated entry.\n")
        self.assertEqual(extract_release_notes(path, "v0.5.71"), "- Undated entry.\n")

    def test_rejects_a_missing_version(self) -> None:
        path = _changelog(HEADER + "## [0.5.70] - 2026-08-12\n\n- Older entry.\n")
        with self.assertRaises(ReleaseNotesError) as raised:
            extract_release_notes(path, "v0.5.71")
        self.assertIn("found 0", str(raised.exception))

    def test_rejects_a_duplicated_version(self) -> None:
        path = _changelog(
            HEADER
            + "## [0.5.71] - 2026-08-13\n\n- One.\n\n## [0.5.71] - 2026-08-12\n\n- Two.\n"
        )
        with self.assertRaises(ReleaseNotesError) as raised:
            extract_release_notes(path, "v0.5.71")
        self.assertIn("found 2", str(raised.exception))

    def test_rejects_an_empty_section(self) -> None:
        path = _changelog(
            HEADER + "## [0.5.71] - 2026-08-13\n\n## [0.5.70] - 2026-08-12\n\n- Older.\n"
        )
        with self.assertRaises(ReleaseNotesError) as raised:
            extract_release_notes(path, "v0.5.71")
        self.assertIn("empty", str(raised.exception))

    def test_rejects_a_section_with_no_entries(self) -> None:
        path = _changelog(HEADER + "## [0.5.71] - 2026-08-13\n\n### Changed\n")
        with self.assertRaises(ReleaseNotesError) as raised:
            extract_release_notes(path, "v0.5.71")
        self.assertIn("concrete change", str(raised.exception))

    def test_rejects_a_changelog_pointer(self) -> None:
        path = _changelog(
            HEADER + "## [0.5.71] - 2026-08-13\n\n- See changelog for details.\n"
        )
        with self.assertRaises(ReleaseNotesError):
            extract_release_notes(path, "v0.5.71")

    def test_ignores_headings_and_entries_inside_code_fences(self) -> None:
        path = _changelog(
            HEADER
            + "## [0.5.71] - 2026-08-13\n\n```\n## [0.5.70] - 2026-08-12\n- fenced\n```\n\n"
            "- Real entry.\n\n## [0.5.70] - 2026-08-12\n\n- Older.\n"
        )
        notes = extract_release_notes(path, "v0.5.71")
        self.assertIn("- Real entry.", notes)
        self.assertIn("## [0.5.70] - 2026-08-12", notes)
        self.assertNotIn("- Older.", notes)

    def test_rejects_a_section_whose_only_entries_are_fenced(self) -> None:
        path = _changelog(
            HEADER + "## [0.5.71] - 2026-08-13\n\n```\n- fenced only\n```\n"
        )
        with self.assertRaises(ReleaseNotesError):
            extract_release_notes(path, "v0.5.71")

    def test_rejects_a_non_semver_tag(self) -> None:
        path = _changelog(HEADER + "## [0.5.71] - 2026-08-13\n\n- Entry.\n")
        for tag in ("0.5.71", "v0.5", "v0.5.71-rc.1", "release-0.5.71", "v0.5.71 "):
            with self.subTest(tag=tag), self.assertRaises(ReleaseNotesError):
                extract_release_notes(path, tag)


class ShippedChangelogTests(unittest.TestCase):
    """The renderer must succeed on the changelog this repository ships."""

    def test_current_workspace_version_renders_notes(self) -> None:
        root = Path(__file__).resolve().parents[2]
        version = ""
        for line in (root / "Cargo.toml").read_text(encoding="utf-8").splitlines():
            if line.startswith("version = "):
                version = line.split('"')[1]
                break
        self.assertRegex(version, r"^\d+\.\d+\.\d+$")
        notes = extract_release_notes(root / "CHANGELOG.md", f"v{version}")
        self.assertIn("\n- ", "\n" + notes)


if __name__ == "__main__":
    unittest.main()
