"""Behavioral regressions for deterministic daily release preparation."""

from __future__ import annotations

import tempfile
import tomllib
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

    def test_empty_fragment_directory_is_available_to_automatic_releases(self) -> None:
        """A green push may use its commit subject when no author wrote a fragment."""
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(release.load_fragments(Path(directory)), [])

    def test_nonstandard_fragment_aliases_publish_under_changed(self) -> None:
        """Performance and Documentation notes already on main must release under Changed."""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / "pack-hydration.toml").write_text(
                'category = "Performance"\n'
                'summary = "Reuse authenticated pack hydration."\n'
                'crates = ["scanner"]\n',
                encoding="utf-8",
            )
            (path / "docs-note.toml").write_text(
                'category = "Documentation"\n'
                'summary = "Document baseline and history instructions."\n'
                'crates = ["cli"]\n',
                encoding="utf-8",
            )
            fragments = release.load_fragments(path)
            self.assertEqual(
                [fragment.category for fragment in fragments],
                ["Changed", "Changed"],
            )
            rendered = release.render_section("0.5.69", "2026-08-10", fragments)
            self.assertIn("### Changed\n\n", rendered)
            self.assertIn("- Document baseline and history instructions.\n", rendered)
            self.assertIn("- Reuse authenticated pack hydration.\n", rendered)
            self.assertNotIn("### Performance", rendered)
            self.assertNotIn("### Documentation", rendered)

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
        manifest = (
            'version = "0.5.48"\n'
            'a = "=0.5.48"\nb = "=0.5.48"\nc = "=0.5.48"\n'
            'd = "=0.5.48"\ne = "=0.5.48"\n'
        )
        self.assertEqual(
            release.bump_manifest(manifest, "0.5.48", "0.5.49"),
            'version = "0.5.49"\n'
            'a = "=0.5.49"\nb = "=0.5.49"\nc = "=0.5.49"\n'
            'd = "=0.5.49"\ne = "=0.5.49"\n',
        )
        with self.assertRaisesRegex(release.PrepareError, "five exact internal pins"):
            release.bump_manifest(manifest.replace('e = "=0.5.48"\n', ""), "0.5.48", "0.5.49")

    def test_lockfile_updates_exactly_six_workspace_packages(self) -> None:
        """Dependency packages sharing the old version must remain byte-for-byte unchanged."""
        packages = [
            "keyhog",
            "keyhog-core",
            "keyhog-profile",
            "keyhog-scanner",
            "keyhog-sources",
            "keyhog-verifier",
            "peer",
        ]
        source = "".join(
            f'[[package]]\nname = "{name}"\nversion = "0.5.48"\n' for name in packages
        )

        updated = release.bump_lockfile(source, "0.5.48", "0.5.49")

        self.assertEqual(updated.count('version = "0.5.49"'), 6)
        self.assertIn('name = "peer"\nversion = "0.5.48"', updated)

    def test_missing_workspace_lock_entry_fails_before_writes(self) -> None:
        """A stale lockfile must block release preparation instead of publishing split versions."""
        source = "".join(
            f'[[package]]\nname = "{name}"\nversion = "0.5.48"\n'
            for name in (
                "keyhog",
                "keyhog-core",
                "keyhog-profile",
                "keyhog-scanner",
                "keyhog-sources",
            )
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

    def test_automatic_summary_fills_missing_crate_coverage(self) -> None:
        """Synchronized publishing must give every otherwise-unchanged crate a release note."""
        fragments = [
            release.Fragment(Path("one.toml"), "Fixed", "CLI repair.", ("cli",)),
            release.Fragment(Path("two.toml"), "Fixed", "Core repair.", ("core",)),
        ]

        completed = release.complete_fragment_coverage(
            fragments, "Publish the successful main push."
        )

        self.assertEqual(
            completed[-1].crates, ("profile", "scanner", "sources", "verifier")
        )
        self.assertTrue(completed[-1].synthetic)


    def test_publishable_package_discovery_metadata_is_canonical(self) -> None:
        """Every crates.io package must lead users to one live homepage and repository."""
        root = Path(__file__).resolve().parents[2]
        manifests = (
            ("workspace", root / "Cargo.toml"),
            ("keyhog", root / "crates/cli/Cargo.toml"),
            ("keyhog-core", root / "crates/core/Cargo.toml"),
            ("keyhog-profile", root / "crates/profile/Cargo.toml"),
            ("keyhog-scanner", root / "crates/scanner/Cargo.toml"),
            ("keyhog-sources", root / "crates/sources/Cargo.toml"),
            ("keyhog-verifier", root / "crates/verifier/Cargo.toml"),
        )

        for name, path in manifests:
            with self.subTest(package=name):
                document = tomllib.loads(path.read_text())
                package = (
                    document["workspace"]["package"]
                    if name == "workspace"
                    else document["package"]
                )
                self.assertEqual(package["homepage"], "https://santh.dev/keyhog/")
                self.assertEqual(
                    package["repository"], "https://github.com/santhreal/keyhog"
                )

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
                'e = { version = "=0.5.48" }\n'
            )
            (root / "Cargo.toml").write_text(manifest)
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
                    f'[[package]]\nname = "{name}"\nversion = "0.5.48"\n'
                    for name in packages
                )
            )
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
                'crates = ["cli", "core", "profile", "scanner", "sources", "verifier"]\n'
            )
            versioned = (
                root / "README.md",
                root / ".github/actions/keyhog/README.md",
                root / ".github/workflows/action-e2e.yml",
                root / "docs/src/install.md",
            )
            for path in versioned:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("Install KeyHog v0.5.48 exactly.\n")


            preview = release.prepare(root, "0.5.49", "2026-07-28", False)

            self.assertEqual(len(preview), 13)
            self.assertEqual((root / "Cargo.toml").read_text(), manifest)
            self.assertTrue(fragment.exists())
            for path in versioned:
                self.assertEqual(path.read_text(), "Install KeyHog v0.5.48 exactly.\n")

            applied = release.prepare(root, "0.5.49", "2026-07-28", True)

            self.assertEqual(applied, preview)
            self.assertFalse(fragment.exists())
            self.assertIn('version = "0.5.49"', (root / "Cargo.toml").read_text())
            self.assertEqual(
                (root / "Cargo.lock").read_text().count('version = "0.5.49"'), 6
            )
            self.assertIn(
                "## [0.5.49] - 2026-07-28\n\n### Changed\n\n"
                "- Publish one coherent release transaction.",
                (root / "CHANGELOG.md").read_text(),
            )
            for path in versioned:
                self.assertEqual(path.read_text(), "Install KeyHog v0.5.49 exactly.\n")
            for relative in release.CRATE_CHANGELOGS.values():
                self.assertIn(
                    "## 0.5.49 - 2026-07-28\n\n"
                    "- Publish one coherent release transaction.",
                    (root / relative).read_text(),
                )


class RepositoryScopeFragmentTests(unittest.TestCase):
    """A change with no crate behind it still has to be releasable."""

    def test_a_repository_scope_fragment_reaches_only_the_root_changelog(self) -> None:
        """README evidence, the benchmark harness and CI belong in the root notes.

        Requiring at least one crate forced these against a crate they never
        touched, which puts a false claim in a published crate changelog. An
        empty list means repository scope: the root changelog carries it and no
        crate changelog does.
        """
        with tempfile.TemporaryDirectory() as directory:
            changes = Path(directory)
            (changes / "readme.toml").write_text(
                'category = "Changed"\nsummary = "Remeasure the README panels."\ncrates = []\n'
            )
            (changes / "scanner.toml").write_text(
                'category = "Fixed"\nsummary = "Repair exact output."\ncrates = ["scanner"]\n'
            )

            fragments = release.load_fragments(changes)

            self.assertIn(
                "- Remeasure the README panels.",
                release.render_section("0.5.58", "2026-08-04", fragments),
            )
            for crate in release.CRATE_CHANGELOGS:
                self.assertNotIn(
                    "Remeasure the README panels.",
                    release.render_section("0.5.58", "2026-08-04", fragments, crate),
                    f"the {crate} changelog must not claim a repository-scope change",
                )

    def test_a_repository_scope_fragment_does_not_cover_any_crate(self) -> None:
        """It must not suppress the automatic per-crate note.

        Coverage exists so every published crate gets a line for the version it
        ships. A note about the README says nothing about `keyhog-scanner`, so
        it cannot stand in for one.
        """
        fragments = [
            release.Fragment(Path("readme.toml"), "Changed", "Remeasure the panels.", ()),
        ]

        completed = release.complete_fragment_coverage(fragments, "Routine release.")
        synthetic = [item for item in completed if item.synthetic]

        self.assertEqual(len(synthetic), 1)
        self.assertEqual(
            set(synthetic[0].crates),
            set(release.CRATE_CHANGELOGS),
            "every crate still needs its own note",
        )

    def test_an_unknown_crate_is_still_rejected(self) -> None:
        """Allowing an empty list must not allow a misspelled one.

        `crates = ["scaner"]` would otherwise route a real change into no
        changelog at all and look exactly like a deliberate repository-scope
        note.
        """
        with tempfile.TemporaryDirectory() as directory:
            changes = Path(directory)
            (changes / "typo.toml").write_text(
                'category = "Fixed"\nsummary = "Repair output."\ncrates = ["scaner"]\n'
            )

            with self.assertRaises(release.PrepareError) as raised:
                release.load_fragments(changes)

            self.assertIn("unique subset", str(raised.exception))


if __name__ == "__main__":
    unittest.main()
