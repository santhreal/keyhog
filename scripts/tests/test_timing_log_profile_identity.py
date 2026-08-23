#!/usr/bin/env python3
"""Unit tests for `scripts/gates/timing_log_profile_identity.py`."""

from __future__ import annotations

import pathlib
import sys
import tempfile
import unittest

GATES_DIR = pathlib.Path(__file__).resolve().parents[1] / "gates"
sys.path.insert(0, str(GATES_DIR))

import timing_log_profile_identity  # noqa: E402


class TestTimingLogProfileIdentity(unittest.TestCase):
    def test_repo_passes_gate(self):
        """Current repository source tree must pass the timing profile identity gate."""
        self.assertEqual(timing_log_profile_identity.main(), 0)

    def test_detects_raw_perf_trace_timing(self):
        """Gate must catch raw perf-trace lines with ad-hoc matcher timing."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmproot = pathlib.Path(tmpdir)
            crates_dir = tmproot / "crates" / "scanner" / "src"
            crates_dir.mkdir(parents=True)

            rs_file = crates_dir / "dispatch.rs"
            rs_file.write_text(
                'fn bad() {\n    eprintln!("perf-trace gpu: matcher=0.001s coalesce=0.002s");\n}\n',
                encoding="utf-8",
            )

            violations = timing_log_profile_identity.scan_source_files(tmproot)
            self.assertGreaterEqual(len(violations), 1)
            self.assertIn("Raw perf-trace timing line found", violations[0][2])


if __name__ == "__main__":
    unittest.main()
