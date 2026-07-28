import pathlib
import tempfile
import unittest

from scripts import org_audit


class OrgAuditEnvironmentSectionTests(unittest.TestCase):
    def test_code_fence_headings_do_not_start_environment_section(self) -> None:
        src = """# CLI

```markdown
## Environment variables
keyhog scan .
```

## Scan command
keyhog scan .
"""
        self.assertEqual(
            org_audit.scan_commands_under_environment_variables(
                pathlib.Path("docs/src/reference/cli.md"), src
            ),
            [],
        )

    def test_real_environment_section_still_rejects_scan_commands(self) -> None:
        src = """# CLI

## Environment variables

```bash
keyhog scan .
```
"""
        violations = org_audit.scan_commands_under_environment_variables(
            pathlib.Path("docs/src/reference/cli.md"), src
        )
        self.assertEqual(len(violations), 1)
        self.assertIn("docs/src/reference/cli.md:6", violations[0])

    def test_non_markdown_sources_do_not_create_markdown_sections(self) -> None:
        src = """// ## Environment variables
// keyhog scan .
"""
        self.assertEqual(
            org_audit.scan_commands_under_environment_variables(
                pathlib.Path("crates/cli/src/subcommands/scan.rs"), src
            ),
            [],
        )


class OrgAuditArchitectureOwnerTests(unittest.TestCase):
    @staticmethod
    def owner_map_fixture(assignments: dict[str, str]) -> str:
        rows = "\n".join(
            f"| {boundary} | `{reference}` |"
            for boundary, reference in assignments.items()
        )
        return (
            f"{org_audit.ARCHITECTURE_OWNER_HEADING}\n\n"
            "| Boundary | Definitional owner |\n"
            "|---|---|\n"
            f"{rows}\n"
        )

    def test_owner_map_requires_every_load_bearing_boundary(self) -> None:
        assignments = dict(org_audit.REQUIRED_ARCHITECTURE_OWNERS)
        boundary = "Curated source-crate export surface"
        reference = assignments.pop(boundary)
        violations = org_audit.architecture_owner_violations(
            self.owner_map_fixture(assignments)
        )
        self.assertIn(
            f"architecture owner map is missing boundary: {boundary} -> {reference}",
            violations,
        )

    def test_swapped_owners_are_rejected_even_when_reference_set_is_unchanged(
        self,
    ) -> None:
        assignments = dict(org_audit.REQUIRED_ARCHITECTURE_OWNERS)
        cli_boundary = "CLI argument dispatch and setup-error exit routing"
        exit_boundary = "Completed-scan exit precedence"
        cli_owner = assignments[cli_boundary]
        exit_owner = assignments[exit_boundary]
        assignments[cli_boundary], assignments[exit_boundary] = exit_owner, cli_owner

        violations = org_audit.architecture_owner_violations(
            self.owner_map_fixture(assignments)
        )
        self.assertIn(
            f"architecture owner map assigns {cli_boundary} to {exit_owner}; "
            f"expected {cli_owner}",
            violations,
        )
        self.assertIn(
            f"architecture owner map assigns {exit_boundary} to {cli_owner}; "
            f"expected {exit_owner}",
            violations,
        )


    def test_planted_stale_owner_symbol_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            owner = root / "crates" / "core" / "src" / "finding.rs"
            owner.parent.mkdir(parents=True)
            owner.write_text(
                "// fn stale_owner() {}\npub fn actual_owner() {}\n",
                encoding="utf-8",
            )
            violation = org_audit.owner_reference_violation(
                "crates/core/src/finding.rs::stale_owner", root
            )
        self.assertEqual(
            violation,
            "architecture owner symbol does not exist: "
            "crates/core/src/finding.rs::stale_owner",
        )

    def test_planted_missing_owner_path_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            violation = org_audit.owner_reference_violation(
                "crates/verifier/src/missing.rs", pathlib.Path(tmp)
            )
        self.assertEqual(
            violation,
            "architecture owner path does not exist: crates/verifier/src/missing.rs",
        )

    def test_repository_architecture_owner_map_resolves(self) -> None:
        architecture = (
            org_audit.ROOT / "docs" / "src" / "architecture.md"
        ).read_text(encoding="utf-8")
        self.assertEqual(
            org_audit.architecture_owner_violations(architecture),
            [],
        )


class OrgAuditWorkflowEvidenceTests(unittest.TestCase):
    def test_make_delegation_preserves_required_competitor_evidence(self) -> None:
        """The workflow may bind the canonical Make target without duplicating its CLI."""
        workflow = """
        make -C benchmarks gate \\
          GATE_SCANNERS=keyhog,betterleaks,kingfisher \\
          REQUIRE_COMPETITORS=betterleaks,kingfisher
        """
        self.assertTrue(org_audit.workflow_requires_competitor_evidence(workflow))

    def test_missing_required_competitors_remains_rejected(self) -> None:
        """A scanner list alone must not satisfy fail-closed competitor availability."""
        workflow = "make -C benchmarks gate GATE_SCANNERS=keyhog,betterleaks,kingfisher"
        self.assertFalse(org_audit.workflow_requires_competitor_evidence(workflow))


if __name__ == "__main__":
    unittest.main()
