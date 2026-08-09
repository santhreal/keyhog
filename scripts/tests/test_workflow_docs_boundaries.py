"""Behavioral contracts for operator discovery and distinct workflow guides."""

from __future__ import annotations

import re
import unittest

from scripts.gates import workflow_docs_boundaries


class WorkflowDocumentationBoundaryTests(unittest.TestCase):
    """Lock out navigation drift and cross-guide responsibility duplication."""

    def setUp(self) -> None:
        self.texts = workflow_docs_boundaries.canonical_texts()

    def test_checked_in_workflow_guides_have_one_explicit_owner_each(self) -> None:
        """The release documentation must route every workflow without duplicating its contract."""
        self.assertEqual(workflow_docs_boundaries.boundary_issues(self.texts), [])

    def test_readme_cannot_drop_any_canonical_operator_route(self) -> None:
        """A landing-page rewrite must keep Action, direct CI, and mass-scanning paths discoverable."""
        broken = dict(self.texts)
        broken["readme"] = broken["readme"].replace(
            "https://santhreal.github.io/keyhog/guides/mass-scanning.html",
            "missing-mass-guide",
        )

        issues = workflow_docs_boundaries.boundary_issues(broken)

        self.assertEqual(len(issues), 1)
        self.assertIn("readme: missing canonical workflow route", issues[0])
        self.assertIn("mass-scanning.html", issues[0])

    def test_readme_cannot_drop_gpu_mass_worker_or_endpoint_discovery(self) -> None:
        """The landing page must expose mass GPU workers and non-filesystem source entry points."""
        for route in (
            "## GPU-backed mass daemon workers",
            "--github-collaboration",
            "--azure-container-url",
        ):
            with self.subTest(route=route):
                broken = dict(self.texts)
                broken["readme"] = broken["readme"].replace(route, "missing-route")
                issues = workflow_docs_boundaries.boundary_issues(broken)
                self.assertEqual(len(issues), 1)
                self.assertIn(route, issues[0])

    def test_readme_cannot_drop_recipe_chooser_or_release_routes(self) -> None:
        """New users and maintainers must reach commands and release operations from the landing page."""
        for route in (
            "https://santhreal.github.io/keyhog/capabilities.html",
            "https://santhreal.github.io/keyhog/recipes.html",
            "https://santhreal.github.io/keyhog/releasing.html",
        ):
            with self.subTest(route=route):
                broken = dict(self.texts)
                broken["readme"] = broken["readme"].replace(route, "missing-route")
                issues = workflow_docs_boundaries.boundary_issues(broken)
                self.assertEqual(len(issues), 1)
                self.assertIn(route, issues[0])

    def test_recipe_index_must_keep_every_source_family_discoverable(self) -> None:
        """A recipe rewrite must not strand container, cloud, URL, host, or verification users."""
        broken = dict(self.texts)
        broken["recipes"] = broken["recipes"].replace(
            "## Scan a Docker image before you ship it",
            "## Missing artifact recipe",
        )

        issues = workflow_docs_boundaries.boundary_issues(broken)

        self.assertEqual(len(issues), 1)
        self.assertIn("recipes: missing canonical workflow route", issues[0])
        self.assertIn("Docker image", issues[0])

    def test_mass_and_daemon_guides_keep_gpu_mass_worker_contract_discoverable(self) -> None:
        """GPU mass setup must remain explicit in both operator guides."""
        for document, route in (
            ("mass", "### GPU-backed daemon worker"),
            ("daemon", "## GPU-backed mass worker"),
        ):
            with self.subTest(document=document):
                broken = dict(self.texts)
                broken[document] = broken[document].replace(route, "## Missing worker setup")
                issues = workflow_docs_boundaries.boundary_issues(broken)
                self.assertEqual(len(issues), 1)
                self.assertIn(route, issues[0])


    def test_native_metal_route_stays_visible_from_install_to_mass_service(self) -> None:
        """The shipped macOS GPU peer must remain discoverable in every operator path."""
        for document, route in (
            ("readme", "gpu-metal-region-presence"),
            ("install", "--no-default-features --features portable,gpu"),
            ("backends", "CUDA, native Metal, and WGPU"),
            ("mass", "gpu-metal-region-presence"),
            ("daemon", "gpu-metal-region-presence"),
        ):
            with self.subTest(document=document):
                broken = dict(self.texts)
                broken[document] = broken[document].replace(route, "missing-metal-route")
                issues = workflow_docs_boundaries.boundary_issues(broken)
                self.assertEqual(len(issues), 1)
                self.assertIn(document, issues[0])
                self.assertIn(route, issues[0])

    def test_release_guide_keeps_trusted_publisher_and_recovery_routes(self) -> None:
        """Maintainers must retain the trusted-publishing and failed-upload recovery path."""
        broken = dict(self.texts)
        broken["release"] = broken["release"].replace(
            "`rust-lang/crates-io-auth-action`",
            "unspecified registry credential",
        )

        issues = workflow_docs_boundaries.boundary_issues(broken)

        self.assertEqual(len(issues), 1)
        self.assertIn("release: missing canonical workflow route", issues[0])
        self.assertIn("crates-io-auth-action", issues[0])

    def test_release_guide_covers_every_published_crate(self) -> None:
        """Every publish-list member must turn the documentation gate red when omitted."""
        for crate in workflow_docs_boundaries.published_crates():
            with self.subTest(crate=crate):
                broken = dict(self.texts)
                broken["release"] = broken["release"].replace(f"`{crate}`", "")

                issues = workflow_docs_boundaries.boundary_issues(broken)

                self.assertIn(
                    f"release: published crate {crate!r} is missing from the release guide",
                    issues,
                )

    def test_release_guide_rejects_long_lived_registry_secret_instructions(self) -> None:
        """Trusted publishing must not regress to a long-lived repository secret."""
        broken = dict(self.texts)
        broken["release"] += (
            "\nSet the repository Actions secret `CARGO_REGISTRY_TOKEN`.\n"
        )

        issues = workflow_docs_boundaries.boundary_issues(broken)

        self.assertIn(
            "release: guide still requires a long-lived crates.io token instead of trusted publishing",
            issues,
        )

    def test_every_required_usage_decision_turns_the_gate_red_when_removed(self) -> None:
        """Every maintained workflow/profile/coverage decision must fail closed on drift."""
        for document, required in workflow_docs_boundaries.REQUIRED_TEXT.items():
            for route in required:
                with self.subTest(document=document, route=route):
                    broken = dict(self.texts)
                    pattern = r"\s+".join(re.escape(part) for part in route.split())
                    broken[document] = re.sub(
                        pattern,
                        "missing-route",
                        broken[document],
                    )

                    issues = workflow_docs_boundaries.boundary_issues(broken)

                    self.assertTrue(
                        any(
                            issue.startswith(
                                f"{document}: missing canonical workflow route"
                            )
                            and route in issue
                            for issue in issues
                        ),
                        issues,
                    )

    def test_every_known_stale_usage_claim_is_rejected(self) -> None:
        """Wrong install paths, feature profiles, and false-clean claims stay banned."""
        for document, forbidden in workflow_docs_boundaries.FORBIDDEN_TEXT.items():
            for claim in forbidden:
                with self.subTest(document=document, claim=claim):
                    broken = dict(self.texts)
                    broken[document] += f"\n{claim}\n"

                    issues = workflow_docs_boundaries.boundary_issues(broken)

                    self.assertIn(
                        f"{document}: stale or unsafe workflow claim {claim!r}",
                        issues,
                    )

    def test_action_guide_cannot_absorb_provider_specific_ci_recipes(self) -> None:
        """GitLab or Jenkins recipes in the Action guide would recreate two conflicting CI manuals."""
        broken = dict(self.texts)
        broken["action"] += "\n## GitLab CI\n\nDuplicate provider recipe.\n"

        issues = workflow_docs_boundaries.boundary_issues(broken)

        self.assertEqual(issues, ["action: heading belongs to another workflow: '## GitLab CI'"])

    def test_mass_guide_cannot_absorb_action_interface_reference(self) -> None:
        """Action inputs and outputs must remain generated from manifests in the Action guide only."""
        broken = dict(self.texts)
        broken["mass"] += "\n## Inputs\n\nDuplicate Action interface.\n"

        issues = workflow_docs_boundaries.boundary_issues(broken)

        self.assertEqual(issues, ["mass: heading belongs to another workflow: '## Inputs'"])

    def test_wrapped_markdown_links_remain_valid_routes(self) -> None:
        """Normal line wrapping must not produce false boundary failures in Rust Book prose."""
        wrapped = dict(self.texts)
        wrapped["mass"] = wrapped["mass"].replace(
            "[CI integration guide](../workflows/ci.md)",
            "[CI integration\n guide](../workflows/ci.md)",
        )

        self.assertEqual(workflow_docs_boundaries.boundary_issues(wrapped), [])


if __name__ == "__main__":
    unittest.main()
