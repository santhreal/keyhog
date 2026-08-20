#!/usr/bin/env python3
"""Unit tests for unified_counter_ownership gate (Row 99)."""

from __future__ import annotations

import pathlib
import tempfile
import unittest

from scripts.gates.unified_counter_ownership import (
    ATOMIC_STATIC_RE,
    check_counter_ownership,
    find_atomic_statics,
)

REPO = pathlib.Path(__file__).resolve().parents[2]


class TestUnifiedCounterOwnership(unittest.TestCase):
    def test_atomic_static_regex_matches(self):
        self.assertIsNotNone(ATOMIC_STATIC_RE.search("static FOO: AtomicUsize = AtomicUsize::new(0);"))
        self.assertIsNotNone(ATOMIC_STATIC_RE.search("pub static BAR: AtomicU64 = AtomicU64::new(0);"))
        self.assertIsNotNone(ATOMIC_STATIC_RE.search("pub(crate) static BAZ: AtomicBool = AtomicBool::new(false);"))
        self.assertIsNone(ATOMIC_STATIC_RE.search("let x = AtomicUsize::new(0);"))

    def test_repo_satisfies_unified_counter_ownership(self):
        passed, violations = check_counter_ownership(REPO)
        self.assertTrue(passed, f"Repo counter ownership violations: {violations}")
        self.assertEqual(len(violations), 0)

    def test_stray_unmapped_counter_fails_check(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_root = pathlib.Path(tmpdir)
            crates_dir = tmp_root / "crates"
            profile_dir = crates_dir / "profile" / "src"
            other_dir = crates_dir / "scanner" / "src"
            profile_dir.mkdir(parents=True, exist_ok=True)
            other_dir.mkdir(parents=True, exist_ok=True)

            # Minimal valid metrics.rs
            (profile_dir / "metrics.rs").write_text(
                "pub enum CounterId { FilesScanned }\npub enum GaugeId { ResidentMemory }\n",
                encoding="utf-8",
            )

            # Stray counter in scanner that does NOT forward to profile
            (other_dir / "stray.rs").write_text(
                "static STRAY_COUNTER: AtomicUsize = AtomicUsize::new(0);\n",
                encoding="utf-8",
            )

            passed, violations = check_counter_ownership(tmp_root)
            self.assertFalse(passed)
            self.assertTrue(any("STRAY_COUNTER" in v for v in violations))


if __name__ == "__main__":
    unittest.main()
