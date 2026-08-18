"""Unit tests for artifact size ceiling gate (Row 97)."""

from __future__ import annotations

import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/gates"))

import artifact_size_ceiling  # noqa: E402


class TestArtifactSizeCeiling(unittest.TestCase):
    def test_cargo_profiles_pass_validation(self) -> None:
        artifact_size_ceiling.check_cargo_profiles(artifact_size_ceiling.CARGO_TOML)

    def test_platform_size_ceilings_recorded(self) -> None:
        self.assertIn("linux-x86_64", artifact_size_ceiling.PLATFORM_SIZE_CEILINGS)
        self.assertIn("linux-aarch64", artifact_size_ceiling.PLATFORM_SIZE_CEILINGS)
        self.assertIn("macos-x86_64", artifact_size_ceiling.PLATFORM_SIZE_CEILINGS)
        self.assertIn("macos-arm64", artifact_size_ceiling.PLATFORM_SIZE_CEILINGS)
        self.assertIn("windows-x86_64", artifact_size_ceiling.PLATFORM_SIZE_CEILINGS)

        for platform, ceiling in artifact_size_ceiling.PLATFORM_SIZE_CEILINGS.items():
            self.assertGreaterEqual(ceiling, 20 * 1024 * 1024)
            self.assertLessEqual(ceiling, 50 * 1024 * 1024)


if __name__ == "__main__":
    unittest.main()
