"""Contracts for the CI-gated bump + tag-driven crates.io publish workflow."""

from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
RELEASE = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
CI = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
PUBLISH = (ROOT / "scripts/publish.sh").read_text(encoding="utf-8")


class AutomaticReleaseWorkflowTests(unittest.TestCase):
    """Lock out manual, signed, or pre-CI publication regressions."""

    def test_successful_main_ci_gates_bumps_and_tag_push_publishes(self) -> None:
        """Green CI on main still owns bumps; crates.io publish is tag/OIDC only."""
        self.assertIn("workflow_run:", RELEASE)
        self.assertIn("workflows: [CI]", RELEASE)
        self.assertIn("workflow_run.conclusion == 'success'", RELEASE)
        self.assertIn("workflow_run.event == 'push'", RELEASE)
        self.assertIn("workflow_run.head_branch == 'main'", RELEASE)
        # Trusted Publishing rejects workflow_run JWTs, so publish listens for
        # the v* tag push (and workflow_dispatch for already-pushed tags).
        self.assertIn('tags: ["v*"]', RELEASE)
        self.assertIn("workflow_dispatch:", RELEASE)
        bump_idx = RELEASE.index("Bump, changelog, and tag")
        publish_idx = RELEASE.index("name: Publish crates.io packages")
        auth_idx = RELEASE.index("rust-lang/crates-io-auth-action@")
        self.assertLess(bump_idx, publish_idx)
        self.assertLess(publish_idx, auth_idx)
        self.assertNotIn("crates-io-auth", RELEASE[:publish_idx])

    def test_release_prepares_one_patch_commit_before_publication(self) -> None:
        """A green CI must bump versions/tag before the tag-triggered cargo upload."""
        prepare = RELEASE.index("scripts/auto_release.py")
        commit = RELEASE.index('git commit -m "release: v${version}"')
        publish = RELEASE.index("bash scripts/publish.sh")
        self.assertLess(prepare, commit)
        self.assertLess(commit, publish)
        self.assertEqual(RELEASE.count("bash scripts/publish.sh"), 1)

    def test_generated_release_commit_cannot_start_another_release(self) -> None:
        """The bot's version commit must terminate the push-driven release loop."""
        guard = 'if [[ "$author" == "41898282+github-actions[bot]@users.noreply.github.com"'
        self.assertIn('author="$(git show -s --format=%ae "$CI_HEAD_SHA")"', RELEASE)
        self.assertIn(guard, RELEASE)
        self.assertLess(RELEASE.index(guard), RELEASE.index("scripts/auto_release.py"))
        self.assertIn("Automatic release commits do not create another release.", RELEASE)

    def test_release_has_no_signature_or_asset_publication_path(self) -> None:
        """Release automation must not restore signing, attestations, or binary bundles."""
        for obsolete in (
            "gpg",
            "minisign",
            "cosign",
            "attest",
            "publish_release_assets",
            "release-signing",
            "KEYHOG_RELEASE_SIGNING",
        ):
            with self.subTest(obsolete=obsolete):
                self.assertNotIn(obsolete, RELEASE.casefold())

    def test_ci_verdict_excludes_removed_security_gates(self) -> None:
        """Successful CI must not wait on prevention, audit, deny, or adversarial jobs."""
        for obsolete in ("audit-gates:", "strict-runners:", "  deny:", "  audit:"):
            with self.subTest(obsolete=obsolete):
                self.assertNotIn(obsolete, CI)
        # Required push/PR verdict is the slim fast path only.
        self.assertIn("length == 5", CI)

    def test_release_dogfood_build_includes_the_simd_backend_it_exercises(self) -> None:
        """The release dogfood matrix must not request SIMD from a portable-only binary."""
        self.assertIn(
            "cargo build --profile release-fast -p keyhog --features simd",
            CI,
        )

    def test_publisher_uploads_dependency_order_without_release_proofs(self) -> None:
        """Cargo uploads must follow the workspace dependency chain and stop there."""
        self.assertIn(
            "CRATES=(keyhog-core keyhog-profile keyhog-verifier keyhog-sources keyhog-scanner keyhog)",
            PUBLISH,
        )
        self.assertEqual(PUBLISH.count("cargo publish"), 1)
        for obsolete in ("signature", "sbom", "provenance", "license_gate"):
            with self.subTest(obsolete=obsolete):
                self.assertNotIn(obsolete, PUBLISH.casefold())

    def test_publisher_prefers_oidc_trusted_identity_with_token_fallback(self) -> None:
        """Publishing must try OIDC first; repo token is only the fallback while TP is rebuilt."""
        self.assertIn("id-token: write", RELEASE)
        self.assertIn("rust-lang/crates-io-auth-action@", RELEASE)
        self.assertIn("steps.crates-io-auth.outputs.token", RELEASE)
        self.assertIn("continue-on-error: true", RELEASE)
        self.assertIn(
            "steps.crates-io-auth.outputs.token || secrets.CARGO_REGISTRY_TOKEN",
            RELEASE,
        )
        self.assertRegex(
            RELEASE,
            r"rust-lang/crates-io-auth-action@[0-9a-f]{40}",
        )

    def test_release_uploads_source_bound_integrity_receipt_after_publication(self) -> None:
        """Every synchronized six-crate release must retain a reproducible commit and lock receipt."""
        generate = RELEASE.index("scripts/release_integrity_receipt.py")
        publish = RELEASE.index("bash scripts/publish.sh")
        upload = RELEASE.index("keyhog-release-integrity-v")
        self.assertLess(generate, publish)
        self.assertLess(publish, upload)
        self.assertIn('--commit "$(git rev-parse HEAD)"', RELEASE)
        self.assertIn("release-integrity.json", RELEASE)


if __name__ == "__main__":
    unittest.main()
