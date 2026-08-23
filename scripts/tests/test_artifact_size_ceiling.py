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

    def test_mutated_profiles_fail_closed(self) -> None:
        import tempfile
        valid_toml = (
            '[profile.release]\n'
            'opt-level = 3\n'
            'strip = "symbols"\n'
            'debug = false\n'
            'panic = "unwind"\n'
            'overflow-checks = true\n'
        )
        with tempfile.NamedTemporaryFile("w+", suffix=".toml") as tmp:
            tmp.write(valid_toml)
            tmp.flush()
            artifact_size_ceiling.check_cargo_profiles(pathlib.Path(tmp.name))

        # Mutate strip
        with tempfile.NamedTemporaryFile("w+", suffix=".toml") as tmp:
            tmp.write(valid_toml.replace('strip = "symbols"', 'strip = "none"'))
            tmp.flush()
            with self.assertRaises(ValueError):
                artifact_size_ceiling.check_cargo_profiles(pathlib.Path(tmp.name))

        # Mutate debug
        with tempfile.NamedTemporaryFile("w+", suffix=".toml") as tmp:
            tmp.write(valid_toml.replace('debug = false', 'debug = true'))
            tmp.flush()
            with self.assertRaises(ValueError):
                artifact_size_ceiling.check_cargo_profiles(pathlib.Path(tmp.name))

        # Mutate panic
        with tempfile.NamedTemporaryFile("w+", suffix=".toml") as tmp:
            tmp.write(valid_toml.replace('panic = "unwind"', 'panic = "abort"'))
            tmp.flush()
            with self.assertRaises(ValueError):
                artifact_size_ceiling.check_cargo_profiles(pathlib.Path(tmp.name))

        # Mutate overflow-checks
        with tempfile.NamedTemporaryFile("w+", suffix=".toml") as tmp:
            tmp.write(valid_toml.replace('overflow-checks = true', 'overflow-checks = false'))
            tmp.flush()
            with self.assertRaises(ValueError):
                artifact_size_ceiling.check_cargo_profiles(pathlib.Path(tmp.name))


if __name__ == "__main__":
    unittest.main()
