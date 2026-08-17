"""Security contracts for privileged self-hosted workflow runners."""

from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github" / "workflows"
TRUSTED_PR = (
    "github.event_name == 'pull_request' "
    "&& github.event.pull_request.user.login == 'santhreal' "
    "&& github.event.pull_request.head.repo.full_name == github.repository"
)
SELF_HOSTED_LABELS = "fromJSON('[\"self-hosted\",\"linux\",\"x64\",\"axiomexec\",\"keyhog\"]')"


class SelfHostedRunnerLockdownTests(unittest.TestCase):
    """Prevent untrusted pull requests from selecting privileged runners."""

    def test_every_self_hosted_runner_selection_requires_same_repo_santhreal_pr(self) -> None:
        """Every privileged runner expression must fail closed to a hosted runner."""
        selections: list[tuple[Path, int, str]] = []
        for workflow in sorted(WORKFLOWS.glob("*.yml")):
            content = workflow.read_text(encoding="utf-8")
            # Only workflows that trigger on pull_request could be triggered by untrusted actors
            if "pull_request" not in content:
                continue
            for line_number, line in enumerate(content.splitlines(), start=1):
                stripped = line.strip()
                if stripped.startswith("runs-on:") and "self-hosted" in stripped:
                    selections.append((workflow, line_number, stripped))
        for workflow, line_number, selection in selections:
            with self.subTest(workflow=workflow.name, line=line_number):
                self.assertIn(TRUSTED_PR, selection)
                self.assertIn(SELF_HOSTED_LABELS, selection)
                self.assertTrue(selection.endswith("|| 'ubuntu-24.04' }}"))

    def test_self_hosted_runner_lists_cannot_bypass_the_guard_expression(self) -> None:
        """Multiline and matrix runner lists must not hide a privileged label."""
        for workflow in sorted(WORKFLOWS.glob("*.yml")):
            lines = workflow.read_text(encoding="utf-8").splitlines()
            for line_number, line in enumerate(lines, start=1):
                stripped = line.strip()
                if stripped == "runs-on:":
                    self.fail(f"{workflow.name}:{line_number}: multiline runs-on is forbidden")
                if stripped.startswith("runner:") and "self-hosted" in stripped:
                    self.fail(
                        f"{workflow.name}:{line_number}: matrix self-hosted runner bypasses the trust guard"
                    )


if __name__ == "__main__":
    unittest.main()
