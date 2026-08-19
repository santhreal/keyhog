"""Unit tests for `scripts/gates/no_silent_fallbacks.py` shrink-only ratchet (Row 136).

//! WHY: Closes defect class where baseline updater allowed arbitrary candidate
//! set growth instead of enforcing a true shrink-only ratchet (Row 136).
//! Catches candidate set expansion when running `--update-baseline` and verifies
//! that baseline debt can only shrink or remain equal, never grow.
"""

from __future__ import annotations

import io
import pathlib
import re
import tempfile
import unittest
from unittest import mock

from scripts.gates import no_silent_fallbacks as nsf


class NoSilentFallbacksRatchetTests(unittest.TestCase):
    def test_growth_is_rejected_and_baseline_unmodified(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            baseline_path = pathlib.Path(td) / "silent_fallback_baseline.txt"
            seed = {"crates/core/src/a.rs::code_a", "crates/core/src/b.rs::code_b"}
            nsf.write_baseline(seed, baseline_path)

            candidate_growth = {
                "crates/core/src/a.rs::code_a",
                "crates/core/src/b.rs::code_b",
                "crates/scanner/src/c.rs::code_c",
            }
            code, added = nsf.update_baseline_ratchet(candidate_growth, baseline_path)
            self.assertEqual(code, 1)
            self.assertEqual(added, ["crates/scanner/src/c.rs::code_c"])

            # Baseline on disk must be untouched
            loaded = nsf.load_baseline(baseline_path)
            self.assertEqual(loaded, seed)

    def test_shrink_is_allowed_and_updates_file(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            baseline_path = pathlib.Path(td) / "silent_fallback_baseline.txt"
            seed = {"crates/core/src/a.rs::code_a", "crates/core/src/b.rs::code_b"}
            nsf.write_baseline(seed, baseline_path)

            candidate_shrink = {"crates/core/src/a.rs::code_a"}
            code, added = nsf.update_baseline_ratchet(candidate_shrink, baseline_path)
            self.assertEqual(code, 0)
            self.assertEqual(added, [])

            loaded = nsf.load_baseline(baseline_path)
            self.assertEqual(loaded, candidate_shrink)

    def test_equal_count_is_allowed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            baseline_path = pathlib.Path(td) / "silent_fallback_baseline.txt"
            seed = {"crates/core/src/a.rs::code_a", "crates/core/src/b.rs::code_b"}
            nsf.write_baseline(seed, baseline_path)

            code, added = nsf.update_baseline_ratchet(seed, baseline_path)
            self.assertEqual(code, 0)
            self.assertEqual(added, [])

            loaded = nsf.load_baseline(baseline_path)
            self.assertEqual(loaded, seed)

    def test_docstring_count_matches_actual_baseline(self) -> None:
        baseline = nsf.load_baseline()
        doc = nsf.__doc__ or ""
        m = re.search(r"(\d+)\s+audited violations", doc)
        self.assertIsNotNone(m, "docstring must state the audited violations count")
        self.assertEqual(
            int(m.group(1)),
            len(baseline),
            f"docstring count {m.group(1)} != actual baseline count {len(baseline)}",
        )

    def test_cli_update_baseline_refuses_growth_with_names(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            test_baseline = pathlib.Path(td) / "silent_fallback_baseline.txt"
            seed = {"crates/core/src/a.rs::code_a"}
            nsf.write_baseline(seed, test_baseline)

            candidate_growth = {
                "crates/core/src/a.rs::code_a",
                "crates/scanner/src/b.rs::code_b",
            }
            stderr_buf = io.StringIO()
            with mock.patch.object(nsf, "BASELINE", test_baseline), \
                 mock.patch.object(nsf, "collect", return_value=candidate_growth), \
                 mock.patch("sys.stderr", stderr_buf):
                exit_code = nsf.main(["--update-baseline"])

            self.assertEqual(exit_code, 1)
            err_output = stderr_buf.getvalue()
            self.assertIn("FAIL: baseline cannot grow", err_output)
            self.assertIn("crates/scanner/src/b.rs", err_output)
            self.assertIn("code_b", err_output)
            self.assertEqual(nsf.load_baseline(test_baseline), seed)

    def test_self_test_passes(self) -> None:
        self.assertEqual(nsf.self_test(), 0)


if __name__ == "__main__":
    unittest.main()
