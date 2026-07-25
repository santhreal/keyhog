"""Behavioral regressions for release documentation version truth."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "gates" / "docs_truth.py"
SPEC = importlib.util.spec_from_file_location("docs_truth", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class DocumentationVersionTruthTests(unittest.TestCase):
    """Keep operator claims current without relabeling measured binaries."""

    def test_historical_benchmark_version_is_not_a_stale_operator_claim(self) -> None:
        """Measured evidence must retain the exact older binary version after a release bump."""
        text = (
            "Current release v0.5.46.\n"
            "<!-- BENCH:leaderboard:start -->\n"
            "Measured scanner KeyHog v0.5.45, executable sha256 abc123.\n"
            "<!-- BENCH:leaderboard:end -->\n"
        )
        self.assertEqual(MODULE.version_truth_issues(text, "README.md", "v0.5.46"), [])

    def test_stale_version_outside_benchmark_evidence_is_rejected(self) -> None:
        """Install and usage prose must never direct an operator to the previous release."""
        issues = MODULE.version_truth_issues(
            "Install KeyHog v0.5.45.\n", "docs/src/install.md", "v0.5.46"
        )
        self.assertEqual(
            issues,
            ["docs/src/install.md:1: stale version v0.5.45; expected v0.5.46"],
        )

    def test_unbalanced_benchmark_marker_is_rejected(self) -> None:
        """Malformed generated markers must not hide stale operator documentation."""
        issues = MODULE.version_truth_issues(
            "<!-- BENCH:leaderboard:start -->\nKeyHog v0.5.45\n",
            "README.md",
            "v0.5.46",
        )
        self.assertEqual(issues, ["README.md: benchmark start marker without end"])


if __name__ == "__main__":
    unittest.main()
