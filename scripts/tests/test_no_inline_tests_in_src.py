#!/usr/bin/env python3
"""Unit tests for scripts/gates/no_inline_tests_in_src.py (Row 149)."""

import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from scripts.gates.no_inline_tests_in_src import (
    ALLOWED,
    check_workspace_sources,
    has_inline_test_module_or_function,
    is_test_file,
    run_gate,
    validate_allowlist,
)


class TestNoInlineTestsInSrcGate(unittest.TestCase):
    def test_repository_passes_gate(self):
        self.assertEqual(run_gate(ROOT), 0)

    def test_syntax_recognition(self):
        # Direct test function attributes
        self.assertTrue(has_inline_test_module_or_function("#[test]\nfn a() {}"))
        self.assertTrue(has_inline_test_module_or_function("#[test]\r\nfn a() {}"))
        self.assertTrue(has_inline_test_module_or_function("#[test] pub fn a() {}"))
        self.assertTrue(has_inline_test_module_or_function("#[test] async fn a() {}"))
        self.assertTrue(has_inline_test_module_or_function("#[tokio::test]\nasync fn a() {}"))
        self.assertTrue(has_inline_test_module_or_function("#[proptest]\nfn a() {}"))

        # Module declarations with inline bodies
        self.assertTrue(has_inline_test_module_or_function("#[cfg(test)]\nmod tests {\n}"))
        self.assertTrue(has_inline_test_module_or_function("#[cfg(test)]\npub mod tests {\n}"))
        self.assertTrue(has_inline_test_module_or_function("#[cfg(test)]\npub(crate) mod tests {\n}"))
        self.assertTrue(has_inline_test_module_or_function("#[cfg(test)]\npub(in crate::m) mod tests {\n}"))
        self.assertTrue(has_inline_test_module_or_function("#[cfg(all(test, feature = \"x\"))]\nmod tests {\n}"))
        self.assertTrue(has_inline_test_module_or_function("#[cfg(test)] mod inline {}"))
        self.assertTrue(has_inline_test_module_or_function("#[cfg(test)]\nmod split\n{\n}"))

        # Compliant patterns
        self.assertFalse(has_inline_test_module_or_function("#[cfg(test)]\nmod tests;\n"))
        self.assertFalse(has_inline_test_module_or_function("#[cfg(test)]\npub mod tests;\n"))
        self.assertFalse(has_inline_test_module_or_function('#[cfg(test)]\n#[path = "foo.rs"]\nmod foo;\n'))
        self.assertFalse(has_inline_test_module_or_function('// #[test]\nfn a() {}'))
        self.assertFalse(has_inline_test_module_or_function('/* #[test] */\nfn a() {}'))
        self.assertFalse(has_inline_test_module_or_function('* #[test]'))
        self.assertFalse(has_inline_test_module_or_function('const T: &str = "#[test]";'))

    def test_is_test_file(self):
        self.assertTrue(is_test_file(pathlib.Path("crates/cli/src/daemon/client_tests.rs")))
        self.assertTrue(is_test_file(pathlib.Path("crates/cli/src/subcommands/doctor/tests.rs")))
        self.assertTrue(is_test_file(pathlib.Path("crates/cli/src/orchestrator/tests/disabled.rs")))
        self.assertFalse(is_test_file(pathlib.Path("crates/cli/src/lib.rs")))
        self.assertFalse(is_test_file(pathlib.Path("crates/cli/src/main.rs")))

    def test_allowlist_validation_catches_missing_and_stale(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmproot = pathlib.Path(tmpdir)
            (tmproot / "crates/foo/src").mkdir(parents=True)
            clean_file = tmproot / "crates/foo/src/lib.rs"
            clean_file.write_text("pub fn foo() {}\n", encoding="utf-8")

            # Stale allowlist entry
            errors = validate_allowlist(tmproot, {"crates/foo/src/lib.rs": "clean file"})
            self.assertTrue(any("Stale allowlist entry" in e for e in errors))

            # Missing allowlist entry
            errors = validate_allowlist(tmproot, {"crates/foo/src/missing.rs": "missing file"})
            self.assertTrue(any("does not exist on disk" in e for e in errors))

            # Empty reason
            test_file = tmproot / "crates/foo/src/with_test.rs"
            test_file.write_text("#[cfg(test)]\nmod tests {}\n", encoding="utf-8")
            errors = validate_allowlist(tmproot, {"crates/foo/src/with_test.rs": ""})
            self.assertTrue(any("empty justification reason" in e for e in errors))

    def test_check_workspace_sources_flags_unallowlisted_tests(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmproot = pathlib.Path(tmpdir)
            (tmproot / "crates/foo/src").mkdir(parents=True)
            test_file = tmproot / "crates/foo/src/inline.rs"
            test_file.write_text("#[test]\nfn bad() {}\n", encoding="utf-8")

            violations = check_workspace_sources(tmproot, {})
            self.assertEqual(len(violations), 1)
            self.assertIn("Forbidden inline test", violations[0])

            # Allowlisted file passes
            violations = check_workspace_sources(tmproot, {"crates/foo/src/inline.rs": "allowed"})
            self.assertEqual(len(violations), 0)


if __name__ == "__main__":
    unittest.main()
