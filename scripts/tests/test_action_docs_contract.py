"""Behavioral tests for the GitHub Action documentation contract gate."""

from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).parents[1] / "gates/action_docs_contract.py"
SPEC = importlib.util.spec_from_file_location("action_docs_contract", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


MANIFEST = """\
name: Fixture
inputs:
  path:
    description: Path to scan.
    default: '.'
  verify:
    description: Verify findings.
    default: 'false'
outputs:
  findings:
    description: Finding count.
  exit-code:
    description: Raw exit code.
runs:
  using: composite
  steps: []
"""

DOC = """\
# Fixture Action

## Inputs

| Input | Default | Contract |
| --- | --- | --- |
| `path` | `.` | Path to scan. |
| `verify` | `'false'` | Verify findings. |

## Outputs

| Output | Meaning |
| --- | --- |
| `findings` | Finding count. |
| `exit-code` | Raw exit code. |
"""


class ActionDocsContractTests(unittest.TestCase):
    """Lock the public Action manifest and reference tables to one interface."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.root_action = self.root / "action.yml"
        self.nested_action = self.root / "nested-action.yml"
        self.guide = self.root / "guide.md"
        self.readme = self.root / "README.md"
        self.root_action.write_text(MANIFEST, encoding="utf-8")
        self.nested_action.write_text(MANIFEST, encoding="utf-8")
        self.guide.write_text(DOC, encoding="utf-8")
        self.readme.write_text(DOC, encoding="utf-8")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def verify(self) -> None:
        MODULE.verify_contract(
            self.root_action,
            self.nested_action,
            (self.guide, self.readme),
        )

    def test_matching_manifests_and_tables_are_accepted(self) -> None:
        """A release-ready interface must pass when both manifests and both references agree exactly."""
        self.verify()

    def test_documented_default_drift_is_rejected(self) -> None:
        """A copied workflow must not inherit a false documented default after action.yml changes."""
        self.guide.write_text(
            DOC.replace("| `verify` | `'false'` |", "| `verify` | `'true'` |"),
            encoding="utf-8",
        )

        with self.assertRaisesRegex(
            MODULE.ContractError, "input names/defaults differ"
        ):
            self.verify()

    def test_missing_documented_input_is_rejected(self) -> None:
        """Every Action input must remain discoverable in each complete public reference table."""
        self.readme.write_text(
            DOC.replace("| `verify` | `'false'` | Verify findings. |\n", ""),
            encoding="utf-8",
        )

        with self.assertRaisesRegex(
            MODULE.ContractError, "input names/defaults differ"
        ):
            self.verify()

    def test_undocumented_manifest_input_is_rejected(self) -> None:
        """Adding an Action input without documenting its default must block the documentation gate."""
        expanded = MANIFEST.replace(
            "outputs:\n",
            "  preset:\n    description: Detection policy.\n    default: default\noutputs:\n",
        )
        self.root_action.write_text(expanded, encoding="utf-8")
        self.nested_action.write_text(expanded, encoding="utf-8")

        with self.assertRaisesRegex(
            MODULE.ContractError, "input names/defaults differ"
        ):
            self.verify()

    def test_output_drift_is_rejected(self) -> None:
        """A renamed or reordered output must not leave examples reading a stale public field."""
        self.guide.write_text(
            DOC.replace("| `findings` | Finding count. |\n", ""), encoding="utf-8"
        )

        with self.assertRaisesRegex(MODULE.ContractError, "output names/order differ"):
            self.verify()

    def test_duplicate_table_name_is_rejected(self) -> None:
        """A duplicate row must not hide an omitted input behind dictionary overwrite behavior."""
        duplicated = DOC.replace(
            "| `verify` | `'false'` | Verify findings. |",
            "| `verify` | `'false'` | Verify findings. |\n| `verify` | `'false'` | Duplicate. |",
        )
        self.guide.write_text(duplicated, encoding="utf-8")

        with self.assertRaisesRegex(MODULE.ContractError, "duplicate names"):
            self.verify()

    def test_root_and_nested_action_drift_is_rejected(self) -> None:
        """The self-test Action path must not expose defaults different from the Marketplace root Action."""
        self.nested_action.write_text(
            MANIFEST.replace("default: 'false'", "default: 'true'"), encoding="utf-8"
        )

        with self.assertRaisesRegex(MODULE.ContractError, "public interfaces differ"):
            self.verify()

    def test_repository_contract_is_current(self) -> None:
        """The checked-in release references must match the exact Action interface shipped from both paths."""
        MODULE.verify_contract(
            MODULE.ROOT_ACTION,
            MODULE.NESTED_ACTION,
            MODULE.ACTION_DOCS,
        )


if __name__ == "__main__":
    unittest.main()
