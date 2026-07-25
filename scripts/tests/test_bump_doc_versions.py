"""Behavioral regressions for provenance-safe release documentation bumps."""

from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "bump_doc_versions.py"
SPEC = importlib.util.spec_from_file_location("bump_doc_versions", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class DocumentationVersionBumpTests(unittest.TestCase):
    """Lock out release bumps that rewrite measured benchmark provenance."""

    def test_operator_pins_update_but_measured_versions_remain_exact(self) -> None:
        """A release bump must not relabel an older measured executable as the new release."""
        source = (
            "Install with TAG=v0.5.45.\n"
            "<!-- BENCH:leaderboard:start -->\n"
            "Measured scanner: KeyHog v0.5.45, sha256=abc123.\n"
            "<!-- BENCH:leaderboard:end -->\n"
            "Use santhreal/keyhog/.github/actions/keyhog@v0.5.45.\n"
        )

        updated = MODULE.bump_markdown(source, "0.5.45", "0.5.46")

        self.assertIn("TAG=v0.5.46", updated)
        self.assertIn("actions/keyhog@v0.5.46", updated)
        self.assertIn("Measured scanner: KeyHog v0.5.45, sha256=abc123.", updated)
        self.assertNotIn("Measured scanner: KeyHog v0.5.46", updated)

    def test_document_without_current_pin_fails_before_mutation(self) -> None:
        """A stale release file must fail loudly instead of reporting a successful no-op bump."""
        with self.assertRaisesRegex(MODULE.VersionBumpError, "does not contain canonical pin"):
            MODULE.bump_markdown("uses: santhreal/keyhog@v0\n", "0.5.45", "0.5.46")

    def test_unbalanced_generated_marker_fails_closed(self) -> None:
        """A malformed generated block must not let the bumper rewrite provenance ambiguously."""
        source = "TAG=v0.5.45\n<!-- BENCH:leaderboard:start -->\nKeyHog v0.5.45\n"
        with self.assertRaisesRegex(MODULE.VersionBumpError, "without an end marker"):
            MODULE.bump_markdown(source, "0.5.45", "0.5.46")

    def test_file_update_is_atomic_and_preserves_mode(self) -> None:
        """The release helper must preserve executable or read-only mode bits across replacement."""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "guide.md"
            path.write_text("TAG=v0.5.45\n")
            path.chmod(0o640)

            MODULE.bump_file(path, "0.5.45", "0.5.46")

            self.assertEqual(path.read_text(), "TAG=v0.5.46\n")
            self.assertEqual(path.stat().st_mode & 0o777, 0o640)
            self.assertFalse(path.with_name("guide.md.version-bump-tmp").exists())


if __name__ == "__main__":
    unittest.main()
