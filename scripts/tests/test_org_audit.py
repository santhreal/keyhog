import pathlib
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
