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

    def test_readme_and_reports_include_both_mirror_and_homefield_corpora(self) -> None:
        """Multi-corpus benchmark honesty: README must display both mirror and homefield corpora."""
        readme = (Path(__file__).resolve().parents[2] / "README.md").read_text(encoding="utf-8")
        self.assertIn("<!-- BENCH:accuracy:start -->", readme)
        self.assertIn("**mirror**", readme)
        self.assertIn("**homefield**", readme)
        self.assertIn("<!-- BENCH:leaderboard:start -->", readme)
        self.assertIn("#### Synthetic SecretBench-shape mirror corpus", readme)
        self.assertIn("#### Competitor homefield / home-turf rule corpus", readme)

    def test_performance_doc_exists_and_is_linked_in_summary(self) -> None:
        """Multi-corpus benchmark documentation must exist and be wired in mdBook SUMMARY."""
        docs_dir = Path(__file__).resolve().parents[2] / "docs" / "src"
        perf_doc = docs_dir / "performance.md"
        self.assertTrue(perf_doc.is_file(), "docs/src/performance.md must exist")
        summary = (docs_dir / "SUMMARY.md").read_text(encoding="utf-8")
        self.assertIn("./performance.md", summary)


if __name__ == "__main__":
    unittest.main()
