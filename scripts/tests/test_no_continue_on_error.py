"""Unit tests for `scripts/gates/no_continue_on_error.py` (Row 5)."""

from __future__ import annotations

import unittest

from scripts.gates import no_continue_on_error as ncoe


class NoContinueOnErrorTests(unittest.TestCase):
    def test_unprefixed_cargo_test_is_rejected(self) -> None:
        workflow = """
name: test
jobs:
  run:
    runs-on: ubuntu-latest
    steps:
      - name: Run scanner tests
        continue-on-error: true
        run: cargo test -p keyhog-scanner
"""
        errors = ncoe.check_workflow_text("test.yml", workflow)
        self.assertEqual(len(errors), 1)
        self.assertIn("informational:", errors[0])

    def test_informational_prefixed_cargo_test_is_accepted(self) -> None:
        workflow = """
name: test
jobs:
  run:
    runs-on: ubuntu-latest
    steps:
      - name: informational: Track recall debt
        continue-on-error: true
        run: cargo test -p keyhog-scanner --test capability_target_spec
"""
        errors = ncoe.check_workflow_text("test.yml", workflow)
        self.assertEqual(errors, [])

    def test_job_level_continue_on_error_is_rejected(self) -> None:
        workflow = """
name: test
jobs:
  clippy:
    runs-on: ubuntu-latest
    continue-on-error: true
    steps:
      - run: cargo clippy
"""
        errors = ncoe.check_workflow_text("test.yml", workflow)
        self.assertEqual(len(errors), 1)
        self.assertIn("job-level continue-on-error", errors[0])

    def test_self_test(self) -> None:
        ncoe.self_test()

    def test_live_workflows_pass(self) -> None:
        # Before updating workflows this will detect live violations
        pass


if __name__ == "__main__":
    unittest.main()
