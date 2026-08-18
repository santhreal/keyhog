"""Unit tests for `scripts/gates/unsafe_guards.py` (Row 87)."""

from __future__ import annotations

import unittest
from pathlib import Path

from scripts.gates import unsafe_guards as ug


class UnsafeGuardsTests(unittest.TestCase):
    def test_clean_unsafe_block_with_safety_comment(self) -> None:
        code = """
        fn get_uid() -> u32 {
            // SAFETY: getuid has no preconditions and cannot fail.
            unsafe { libc::getuid() }
        }
        """
        sites = ug.scan_file_for_unsafe(Path("test.rs"), code)
        self.assertEqual(sites, [])

    def test_clean_unsafe_block_with_assert_and_safety_comment(self) -> None:
        code = """
        fn access(slice: &[u8], idx: usize) -> u8 {
            assert!(idx < slice.len(), "out of bounds");
            // SAFETY: index checked above.
            unsafe { *slice.get_unchecked(idx) }
        }
        """
        sites = ug.scan_file_for_unsafe(Path("test.rs"), code)
        self.assertEqual(sites, [])

    def test_debug_assert_preceding_unsafe_fails(self) -> None:
        code = """
        fn access(slice: &[u8], idx: usize) -> u8 {
            debug_assert!(idx < slice.len());
            // SAFETY: checked by debug_assert
            unsafe { *slice.get_unchecked(idx) }
        }
        """
        sites = ug.scan_file_for_unsafe(Path("test.rs"), code)
        self.assertEqual(len(sites), 1)
        self.assertTrue(sites[0].has_debug_assert_hazard)
        self.assertIn("Preceded by `debug_assert!` without release `assert!`", sites[0].details)

    def test_missing_safety_comment_fails(self) -> None:
        code = """
        fn get_pid() -> u32 {
            unsafe { libc::getpid() as u32 }
        }
        """
        sites = ug.scan_file_for_unsafe(Path("test.rs"), code)
        self.assertEqual(len(sites), 1)
        self.assertFalse(sites[0].has_safety_comment)
        self.assertIn("Missing required `// SAFETY:` comment", sites[0].details)

    def test_string_literal_with_unsafe_is_ignored(self) -> None:
        code = """
        fn log() {
            let msg = "docker manifest references unsafe {kind} path";
        }
        """
        sites = ug.scan_file_for_unsafe(Path("test.rs"), code)
        self.assertEqual(sites, [])

    def test_line_comment_with_unsafe_is_ignored(self) -> None:
        code = """
        fn helper() {
            // this is an unsafe pattern explanation
            let x = 42;
        }
        """
        sites = ug.scan_file_for_unsafe(Path("test.rs"), code)
        self.assertEqual(sites, [])


if __name__ == "__main__":
    unittest.main()
