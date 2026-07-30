"""Behavioral contracts for distinct Action, direct CI, and inventory guides."""

from __future__ import annotations

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
