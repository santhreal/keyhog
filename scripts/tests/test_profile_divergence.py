"""Unit tests for `scripts/gates/profile_divergence.py`."""

from __future__ import annotations

import unittest
from pathlib import Path

from scripts.gates import profile_divergence as pd


class ProfileClassificationTests(unittest.TestCase):
    def test_known_semantic_and_cosmetic_keys(self) -> None:
        valid_profiles = {
            "release": {
                "opt-level": 3,
                "lto": "fat",
                "codegen-units": 1,
                "panic": "unwind",
                "strip": "symbols",
                "debug": False,
                "incremental": False,
                "overflow-checks": True,
            },
            "release-fast": {
                "inherits": "release",
                "lto": "thin",
                "codegen-units": 16,
                "strip": "none",
                "debug-assertions": True,
            },
            "ci-test": {
                "inherits": "release-fast",
                "lto": False,
                "codegen-units": 256,
                "panic": "unwind",
            },
            "bench": {
                "inherits": "release",
                "debug": "line-tables-only",
                "strip": "none",
            },
        }
        errors, warnings = pd.classify_profile_keys(valid_profiles)
        self.assertEqual(errors, [])
        self.assertEqual(warnings, [])

    def test_unclassified_key_fails_closed(self) -> None:
        profiles = {
            "release": {
                "panic": "unwind",
                "overflow-checks": True,
                "novel-unclassified-profile-key": "some-value",
            }
        }
        errors, _ = pd.classify_profile_keys(profiles)
        self.assertTrue(bool(errors))
        self.assertTrue(
            any(
                "Unclassified key" in e and "novel-unclassified-profile-key" in e
                for e in errors
            )
        )

    def test_release_panic_abort_fails(self) -> None:
        profiles = {
            "release": {
                "panic": "abort",
                "overflow-checks": True,
            }
        }
        errors, _ = pd.classify_profile_keys(profiles)
        self.assertTrue(
            any("panic strategy must be 'unwind'" in e for e in errors)
        )

    def test_release_overflow_checks_false_fails(self) -> None:
        profiles = {
            "release": {
                "panic": "unwind",
                "overflow-checks": False,
            }
        }
        errors, _ = pd.classify_profile_keys(profiles)
        self.assertTrue(
            any("overflow-checks must be true" in e for e in errors)
        )

    def test_missing_release_profile_fails(self) -> None:
        profiles = {
            "dev": {
                "opt-level": 0,
            }
        }
        errors, _ = pd.classify_profile_keys(profiles)
        self.assertTrue(
            any("Missing required [profile.release]" in e for e in errors)
        )


if __name__ == "__main__":
    unittest.main()
