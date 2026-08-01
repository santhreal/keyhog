"""Behavioral regressions for push-driven patch releases."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from scripts import auto_release
from scripts import prepare_release


class AutomaticReleaseTests(unittest.TestCase):
    """Prove successful main pushes become coherent patch releases."""

    def make_workspace(self, root: Path) -> None:
        """Create the smallest workspace that exercises every release-owned surface."""
        (root / "Cargo.toml").write_text(
            '[workspace.package]\nversion = "0.5.49"\n'
            '[workspace.dependencies]\n'
            'a = { version = "=0.5.49" }\n'
            'b = { version = "=0.5.49" }\n'
            'c = { version = "=0.5.49" }\n'
            'd = { version = "=0.5.49" }\n'
            'e = { version = "=0.5.49" }\n',
            encoding="utf-8",
        )
        packages = (
            "keyhog",
            "keyhog-core",
            "keyhog-profile",
            "keyhog-scanner",
            "keyhog-sources",
            "keyhog-verifier",
        )
        (root / "Cargo.lock").write_text(
            "".join(
                f'[[package]]\nname = "{name}"\nversion = "0.5.49"\n'
                for name in packages
            ),
            encoding="utf-8",
        )
        (root / "CHANGELOG.md").write_text(
            "# Changelog\n\n## [0.5.49] - 2026-07-31\n\n### Changed\n\n- Old.\n",
            encoding="utf-8",
        )
        for relative in prepare_release.CRATE_CHANGELOGS.values():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(
                "# Changelog\n\n## 0.5.49 - 2026-07-31\n\n- Old.\n",
                encoding="utf-8",
            )
        changes = root / "changes"
        changes.mkdir()
        (changes / ".gitkeep").touch()

    def test_patch_increment_preserves_major_and_minor(self) -> None:
        """Every green push must advance exactly one patch without inventing a release line."""
        self.assertEqual(auto_release.next_patch_version("0.5.49"), "0.5.50")
        self.assertEqual(auto_release.next_patch_version("12.34.999"), "12.34.1000")

    def test_commit_subject_normalizes_to_one_changelog_sentence(self) -> None:
        """Whitespace from a push payload must not corrupt generated Markdown sections."""
        self.assertEqual(
            auto_release.release_summary("  speed:   fuse scanner lanes  "),
            "speed: fuse scanner lanes.",
        )
        with self.assertRaisesRegex(auto_release.AutoReleaseError, "contain text"):
            auto_release.release_summary(" -- ")
        with self.assertRaisesRegex(auto_release.AutoReleaseError, "240"):
            auto_release.release_summary("x" * 241)

    def test_push_without_fragments_updates_every_crate_and_consumes_nothing(self) -> None:
        """A green push without authored fragments must still produce complete crate changelogs."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_workspace(root)

            version, changed = auto_release.prepare_next_release(
                root, "perf: remove redundant scans", "2026-08-01", True
            )

            self.assertEqual(version, "0.5.50")
            self.assertEqual(len(changed), 9)
            self.assertTrue((root / "changes/.gitkeep").exists())
            self.assertIn(
                "## [0.5.50] - 2026-08-01\n\n### Changed\n\n"
                "- perf: remove redundant scans.",
                (root / "CHANGELOG.md").read_text(encoding="utf-8"),
            )
            for relative in prepare_release.CRATE_CHANGELOGS.values():
                self.assertIn(
                    "## 0.5.50 - 2026-08-01\n\n- perf: remove redundant scans.",
                    (root / relative).read_text(encoding="utf-8"),
                )

    def test_partial_fragments_keep_authored_note_and_fill_missing_crates(self) -> None:
        """An authored crate note must survive while uncovered crates receive the push subject."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_workspace(root)
            fragment = root / "changes/scanner.toml"
            fragment.write_text(
                'category = "Fixed"\nsummary = "Repair scanner batching."\n'
                'crates = ["scanner"]\n',
                encoding="utf-8",
            )

            auto_release.prepare_next_release(
                root, "perf: reduce allocations", "2026-08-01", True
            )

            self.assertFalse(fragment.exists())
            scanner = (root / "crates/scanner/CHANGELOG.md").read_text(encoding="utf-8")
            core = (root / "crates/core/CHANGELOG.md").read_text(encoding="utf-8")
            self.assertIn("Repair scanner batching.", scanner)
            self.assertNotIn("perf: reduce allocations.", scanner)
            self.assertIn("perf: reduce allocations.", core)


if __name__ == "__main__":
    unittest.main()
