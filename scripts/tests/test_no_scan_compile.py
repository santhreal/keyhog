#!/usr/bin/env python3
"""Unit tests for scripts/gates/no_scan_compile.py (Row 124)."""

import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from scripts.gates.no_scan_compile import (
    CANONICAL_ENTRY_POINTS_FILE,
    ORCHESTRATOR_FILE,
    SCAN_ARGS_FILE,
    check_developer_flag_hidden,
    check_orchestrator_scan_path_guarded,
    check_permitted_entry_points,
    run_gate,
)


class TestNoScanCompileGate(unittest.TestCase):
    def test_repository_passes_gate(self):
        self.assertEqual(run_gate(ROOT), 0)

    def test_permitted_entry_points_checked(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmproot = pathlib.Path(tmpdir)
            target = tmproot / CANONICAL_ENTRY_POINTS_FILE
            target.parent.mkdir(parents=True, exist_ok=True)

            target.write_text(
                'pub const PERMITTED_DETECTOR_COMPILATION_ENTRY_POINTS: &[&str] = &["install", "update"];\n',
                encoding="utf-8",
            )
            self.assertEqual(check_permitted_entry_points(tmproot), [])

            target.write_text(
                'pub const PERMITTED_DETECTOR_COMPILATION_ENTRY_POINTS: &[&str] = &["install", "update", "scan"];\n',
                encoding="utf-8",
            )
            errors = check_permitted_entry_points(tmproot)
            self.assertEqual(len(errors), 1)

    def test_developer_flag_hidden(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmproot = pathlib.Path(tmpdir)
            target = tmproot / SCAN_ARGS_FILE
            target.parent.mkdir(parents=True, exist_ok=True)

            target.write_text(
                '#[arg(long = "developer-compile-embedded-detectors", hide = true)]\npub developer_compile_embedded_detectors: bool,\n',
                encoding="utf-8",
            )
            self.assertEqual(check_developer_flag_hidden(tmproot), [])

            target.write_text(
                '#[arg(long = "developer-compile-embedded-detectors")]\npub developer_compile_embedded_detectors: bool,\n',
                encoding="utf-8",
            )
            errors = check_developer_flag_hidden(tmproot)
            self.assertEqual(len(errors), 1)

    def test_orchestrator_guarded(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmproot = pathlib.Path(tmpdir)
            target = tmproot / ORCHESTRATOR_FILE
            target.parent.mkdir(parents=True, exist_ok=True)

            target.write_text(
                'if !args.developer_compile_embedded_detectors { bail!(); } keyhog_scanner::compile_shared_with_matcher_artifact_cache(...);\n',
                encoding="utf-8",
            )
            self.assertEqual(check_orchestrator_scan_path_guarded(tmproot), [])

            target.write_text(
                'let scanner = keyhog_scanner::compile_shared_with_matcher_artifact_cache(...);\n',
                encoding="utf-8",
            )
            errors = check_orchestrator_scan_path_guarded(tmproot)
            self.assertEqual(len(errors), 1)


if __name__ == "__main__":
    unittest.main()
