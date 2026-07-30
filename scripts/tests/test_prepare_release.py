"""Behavioral regressions for deterministic daily release preparation."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from scripts import prepare_release as release


class ReleaseFragmentTests(unittest.TestCase):
    """Lock out ambiguous or incomplete release-note inputs."""

    def test_fragment_order_and_category_order_are_deterministic(self) -> None:
        """Release notes must not vary with filesystem enumeration or author entry order."""
        with tempfile.TemporaryDirectory() as directory:
            changes = Path(directory)
            (changes / "z-fix.toml").write_text(
                'category = "Fixed"\nsummary = "Repair exact output."\ncrates = ["scanner"]\n'
            )
            (changes / "a-add.toml").write_text(
                'category = "Added"\nsummary = "Add one operator command."\ncrates = ["cli", "core"]\n'
            )

            fragments = release.load_fragments(changes)
            rendered = release.render_section("0.5.49", "2026-07-28", fragments)

            self.assertEqual([item.path.name for item in fragments], ["a-add.toml", "z-fix.toml"])
            self.assertEqual(
                rendered,
                "## [0.5.49] - 2026-07-28\n\n"
                "### Added\n\n- Add one operator command.\n\n"
                "### Fixed\n\n- Repair exact output.\n\n",
            )

    def test_crate_section_contains_only_owned_changes(self) -> None:
        """A published crate changelog must not claim a change owned by another package."""
        fragments = [
            release.Fragment(Path("a.toml"), "Added", "CLI addition.", ("cli",)),
            release.Fragment(Path("b.toml"), "Fixed", "Scanner repair.", ("scanner",)),
        ]

        rendered = release.render_section("0.5.49", "2026-07-28", fragments, "scanner")

        self.assertEqual(rendered, "## 0.5.49 - 2026-07-28\n\n- Scanner repair.\n\n")
        self.assertNotIn("CLI addition", rendered)

    def test_empty_fragment_directory_fails_closed(self) -> None:
        """A daily tag must not publish an empty or placeholder GitHub release body."""
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(release.PrepareError, "no release change fragments"):
                release.load_fragments(Path(directory))

    def test_unknown_fields_and_crates_are_rejected(self) -> None:
        """Typos in fragment ownership must not silently disappear from crate notes."""
        invalid = (
            'category = "Fixed"\nsummary = "Repair."\ncrates = ["unknown"]\n',
            'category = "Fixed"\nsummary = "Repair."\ncrates = ["cli"]\nextra = true\n',
        )
        for body in invalid:
            with self.subTest(body=body), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "repair.toml"
                path.write_text(body)
                with self.assertRaises(release.PrepareError):
                    release.load_fragments(path.parent)

    def test_duplicate_and_multiline_summaries_are_rejected(self) -> None:
        """Release notes must contain one unambiguous statement per fragment."""
        with tempfile.TemporaryDirectory() as directory:
            changes = Path(directory)
            (changes / "a.toml").write_text(
                'category = "Fixed"\nsummary = "Same repair."\ncrates = ["cli"]\n'
            )
            (changes / "b.toml").write_text(
                'category = "Changed"\nsummary = "same repair."\ncrates = ["core"]\n'
            )
            with self.assertRaisesRegex(release.PrepareError, "duplicate"):
                release.load_fragments(changes)


class ReleaseTransformationTests(unittest.TestCase):
    """Prove version and changelog transformations fail closed on drift."""

    def test_versions_must_be_canonical_and_increase(self) -> None:
        """The preparer must reject ambiguous or backwards tags before touching files."""
        for value in ("v0.5.49", "0.05.49", "0.5", "0.5.49-rc.1"):
            with self.subTest(value=value), self.assertRaises(release.PrepareError):
                release.parse_version(value)
        self.assertEqual(release.parse_version("10.20.30"), (10, 20, 30))

    def test_manifest_requires_every_internal_pin(self) -> None:
        """A release cannot mix workspace package versions across crates.io artifacts."""
        manifest = 'version = "0.5.48"\na = "=0.5.48"\nb = "=0.5.48"\nc = "=0.5.48"\nd = "=0.5.48"\n'
        self.assertEqual(
            release.bump_manifest(manifest, "0.5.48", "0.5.49"),
            'version = "0.5.49"\na = "=0.5.49"\nb = "=0.5.49"\nc = "=0.5.49"\nd = "=0.5.49"\n',
        )
        with self.assertRaisesRegex(release.PrepareError, "four exact internal pins"):
            release.bump_manifest(manifest.replace('d = "=0.5.48"\n', ""), "0.5.48", "0.5.49")

    def test_lockfile_updates_exactly_five_workspace_packages(self) -> None:
        """Dependency packages sharing the old version must remain byte-for-byte unchanged."""
        packages = ["keyhog", "keyhog-core", "keyhog-scanner", "keyhog-sources", "keyhog-verifier", "peer"]
        source = "".join(
            f'[[package]]\nname = "{name}"\nversion = "0.5.48"\n' for name in packages
        )

        updated = release.bump_lockfile(source, "0.5.48", "0.5.49")

        self.assertEqual(updated.count('version = "0.5.49"'), 5)
        self.assertIn('name = "peer"\nversion = "0.5.48"', updated)

    def test_missing_workspace_lock_entry_fails_before_writes(self) -> None:
        """A stale lockfile must block release preparation instead of publishing split versions."""
        source = "".join(
            f'[[package]]\nname = "{name}"\nversion = "0.5.48"\n'
            for name in ("keyhog", "keyhog-core", "keyhog-scanner", "keyhog-sources")
        )
        with self.assertRaisesRegex(release.PrepareError, "keyhog-verifier"):
            release.bump_lockfile(source, "0.5.48", "0.5.49")

    def test_release_insertion_preserves_preamble_and_history(self) -> None:
        """Automated preparation must add one newest section without rewriting old notes."""
        source = "# Changelog\n\nPolicy.\n\n## [0.5.48] - 2026-07-27\n\n### Fixed\n\n- Old.\n"
        section = "## [0.5.49] - 2026-07-28\n\n### Added\n\n- New.\n\n"

        updated = release.insert_release(source, section)

        self.assertEqual(updated, "# Changelog\n\nPolicy.\n\n" + section + source[source.index("## [0.5.48]"):])

    def test_hand_maintained_unreleased_section_is_rejected(self) -> None:
        """Generated fragments and handwritten drafts must never merge by accidental precedence."""
        source = "# Changelog\n\n## [Unreleased]\n\n- Draft.\n\n## [0.5.48]\n"
        with self.assertRaisesRegex(release.PrepareError, "hand-maintained"):
            release.insert_release(source, "## [0.5.49]\n")

    def test_release_chain_requires_owned_notes_for_every_crate(self) -> None:
        """A synchronized five-crate publish must not create an empty crate release section."""
        fragments = [
            release.Fragment(Path("one.toml"), "Fixed", "CLI repair.", ("cli",)),
            release.Fragment(Path("two.toml"), "Fixed", "Core repair.", ("core",)),
        ]
        with self.assertRaisesRegex(release.PrepareError, "scanner.*sources.*verifier"):
            release.validate_crate_coverage(fragments)

    def test_complete_preview_is_read_only_and_apply_consumes_fragments(self) -> None:
        """One command must coherently prepare every release surface without mutating previews."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = (
                '[workspace.package]\nversion = "0.5.48"\n'
                '[workspace.dependencies]\n'
                'a = { version = "=0.5.48" }\n'
                'b = { version = "=0.5.48" }\n'
                'c = { version = "=0.5.48" }\n'
                'd = { version = "=0.5.48" }\n'
            )
            (root / "Cargo.toml").write_text(manifest)
            packages = (
                "keyhog",
                "keyhog-core",
                "keyhog-scanner",
                "keyhog-sources",
                "keyhog-verifier",
            )
            (root / "Cargo.lock").write_text(
                "".join(
                    f'[[package]]\nname = "{name}"\nversion = "0.5.48"\n'
                    for name in packages
                )
            )
            for relative in release.VERSIONED_FILES:
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("Install KeyHog v0.5.48.\n")
            (root / "CHANGELOG.md").write_text(
                "# Changelog\n\n## [0.5.48] - 2026-07-27\n\n### Fixed\n\n- Old root.\n"
            )
            for relative in release.CRATE_CHANGELOGS.values():
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(
                    "# Changelog\n\n## 0.5.48 - 2026-07-27\n\n- Old crate.\n"
                )
            changes = root / "changes"
            changes.mkdir()
            fragment = changes / "release-transaction.toml"
            fragment.write_text(
                'category = "Changed"\n'
                'summary = "Publish one coherent release transaction."\n'
                'crates = ["cli", "core", "scanner", "sources", "verifier"]\n'
            )

            preview = release.prepare(root, "0.5.49", "2026-07-28", False)

            self.assertEqual(len(preview), 22)
            self.assertEqual((root / "Cargo.toml").read_text(), manifest)
            self.assertTrue(fragment.exists())

            applied = release.prepare(root, "0.5.49", "2026-07-28", True)

            self.assertEqual(applied, preview)
            self.assertFalse(fragment.exists())
            self.assertIn('version = "0.5.49"', (root / "Cargo.toml").read_text())
            self.assertEqual(
                (root / "Cargo.lock").read_text().count('version = "0.5.49"'), 5
            )
            self.assertIn(
                "## [0.5.49] - 2026-07-28\n\n### Changed\n\n"
                "- Publish one coherent release transaction.",
                (root / "CHANGELOG.md").read_text(),
            )
            for relative in release.CRATE_CHANGELOGS.values():
                self.assertIn(
                    "## 0.5.49 - 2026-07-28\n\n"
                    "- Publish one coherent release transaction.",
                    (root / relative).read_text(),
                )
            for relative in release.VERSIONED_FILES:
                self.assertEqual(
                    (root / relative).read_text(), "Install KeyHog v0.5.49.\n"
                )


if __name__ == "__main__":
    unittest.main()
