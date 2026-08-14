"""Contracts for external registry dependency publication preflight."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts import publish_registry_preflight as preflight


class RegistryDependencyPreflightTests(unittest.TestCase):
    def manifest(self, body: str) -> Path:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        path = Path(directory.name) / "Cargo.toml"
        path.write_text(body, encoding="utf-8")
        return path

    def test_registry_fallbacks_derive_every_versioned_git_dependency(self) -> None:
        manifest = self.manifest(
            "[workspace.dependencies]\n"
            'plain = "1.0.0"\n'
            'alpha = { version = "=2.3.4", git = "https://example/alpha" }\n'
            'beta_alias = { package = "beta", version = "=5.6.7", git = "https://example/beta" }\n'
        )

        self.assertEqual(
            preflight.registry_fallbacks(manifest),
            [("alpha", "2.3.4"), ("beta", "5.6.7")],
        )

    def test_nonexact_publishable_git_dependency_fails_closed(self) -> None:
        manifest = self.manifest(
            "[workspace.dependencies]\n"
            'alpha = { version = "2.3", git = "https://example/alpha" }\n'
        )

        with self.assertRaisesRegex(preflight.PreflightError, "exact registry version"):
            preflight.registry_fallbacks(manifest)

    def test_missing_sibling_registry_versions_block_before_upload(self) -> None:
        manifest = self.manifest(
            "[workspace.dependencies]\n"
            'alpha = { version = "=2.3.4", git = "https://example/alpha" }\n'
            'beta = { version = "=5.6.7", git = "https://example/beta" }\n'
        )
        with mock.patch.object(
            preflight,
            "crate_version_visible",
            side_effect=lambda package, _version: package == "alpha",
        ):
            with self.assertRaisesRegex(preflight.PreflightError, "beta 5.6.7"):
                preflight.verify(manifest)


if __name__ == "__main__":
    unittest.main()
