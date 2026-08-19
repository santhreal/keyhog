#!/usr/bin/env python3
"""Unit tests for scripts/gates/no_cwd_relative_source_reads.py (Row 149)."""

import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from scripts.gates.no_cwd_relative_source_reads import (
    check_workspace_tests,
    find_cwd_relative_source_read,
    is_crate_source_literal,
    run_gate,
    scan_file_for_cwd_relative_reads,
)


class TestNoCwdRelativeSourceReadsGate(unittest.TestCase):
    def test_repository_passes_gate(self):
        self.assertEqual(run_gate(ROOT), 0)

    def test_crate_source_literal_classification(self):
        self.assertTrue(is_crate_source_literal("src/lib.rs"))
        self.assertTrue(is_crate_source_literal("src/foo/bar.rs"))
        self.assertTrue(is_crate_source_literal("crates/core/src/lib.rs"))
        self.assertTrue(is_crate_source_literal("../cli/src/main.rs"))

        self.assertFalse(is_crate_source_literal("fixtures/sample.json"))
        self.assertFalse(is_crate_source_literal("./tests/fixtures/sample.json"))
        self.assertFalse(is_crate_source_literal("/tmp/src/foo.rs"))
        self.assertFalse(is_crate_source_literal("target/debug/foo"))

    def test_find_cwd_relative_source_read_detection(self):
        # Positive cases
        self.assertEqual(
            find_cwd_relative_source_read('let s = std::fs::read_to_string("src/foo.rs");'),
            "src/foo.rs",
        )
        self.assertEqual(
            find_cwd_relative_source_read('let s = read_to_string("crates/core/src/lib.rs");'),
            "crates/core/src/lib.rs",
        )
        self.assertEqual(
            find_cwd_relative_source_read('let s = read_to_string("../cli/src/main.rs");'),
            "../cli/src/main.rs",
        )
        self.assertEqual(
            find_cwd_relative_source_read('let f = File::open("src/spec/validate.rs");'),
            "src/spec/validate.rs",
        )
        self.assertEqual(
            find_cwd_relative_source_read('let b = fs::read("src/calibration.rs");'),
            "src/calibration.rs",
        )
        self.assertEqual(
            find_cwd_relative_source_read('let s = read_to_string(  "src/x.rs"  );'),
            "src/x.rs",
        )
        self.assertEqual(
            find_cwd_relative_source_read('let f = std::fs::File::open("src/bar.rs");'),
            "src/bar.rs",
        )

        # Negative cases
        self.assertIsNone(find_cwd_relative_source_read('// read_to_string("src/foo.rs")'))
        self.assertIsNone(find_cwd_relative_source_read('/* read_to_string("src/foo.rs") */'))
        self.assertIsNone(find_cwd_relative_source_read('* read_to_string("src/foo.rs")'))
        self.assertIsNone(
            find_cwd_relative_source_read('let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/foo.rs");')
        )
        self.assertIsNone(
            find_cwd_relative_source_read('let s = keyhog_core::testing::read_crate_source("src/foo.rs");')
        )
        self.assertIsNone(find_cwd_relative_source_read('let s = read_to_string("fixtures/test.json");'))
        self.assertIsNone(find_cwd_relative_source_read('let s = read_to_string("/tmp/src/foo.rs");'))

    def test_scan_file_and_workspace_check(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmproot = pathlib.Path(tmpdir)
            test_dir = tmproot / "crates/foo/tests"
            test_dir.mkdir(parents=True)
            bad_test = test_dir / "bad_test.rs"
            bad_test.write_text(
                '#[test]\nfn test_something() {\n    let s = std::fs::read_to_string("src/foo.rs");\n}\n',
                encoding="utf-8",
            )

            violations = check_workspace_tests(tmproot)
            self.assertEqual(len(violations), 1)
            self.assertIn("CWD-relative source read `src/foo.rs`", violations[0])


if __name__ == "__main__":
    unittest.main()
