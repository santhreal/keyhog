import pathlib
import subprocess
import tempfile
import unittest
from unittest import mock

from scripts.gates import complexity_budget


class ExactComplexityRatchetTests(unittest.TestCase):
    def test_exact_measurement_has_no_drift(self) -> None:
        measured = {"engine_files": 39, "engine_loc": 11_659}
        self.assertEqual(
            complexity_budget.budget_drift(measured, measured.copy()),
            [],
        )

    def test_planted_slack_is_rejected(self) -> None:
        measured = {"engine_files": 39, "engine_loc": 11_659}
        budget = {"engine_files": 40, "engine_loc": 12_121}
        self.assertEqual(
            complexity_budget.budget_drift(measured, budget),
            [
                ("engine_files", 39, 40),
                ("engine_loc", 11_659, 12_121),
            ],
        )

    def test_growth_and_unbudgeted_metrics_are_rejected(self) -> None:
        measured = {"engine_files": 40, "engine_loc": 11_659, "phase2_lanes": 10}
        budget = {"engine_files": 39, "engine_loc": 11_659}
        self.assertEqual(
            complexity_budget.budget_drift(measured, budget),
            [
                ("engine_files", 40, 39),
                ("phase2_lanes", 10, None),
            ],
        )

    def test_new_backend_variant_breaches_exact_owner_ratchet(self) -> None:
        original = """\
#[non_exhaustive]
pub enum ScanBackend {
    GpuCuda,
    GpuWgpu,
    GpuMetal,
    SimdCpu,
    CpuFallback,
}
"""
        expanded = original.replace("    CpuFallback,\n", "    Experimental,\n    CpuFallback,\n")
        with tempfile.TemporaryDirectory() as tmp:
            owner = pathlib.Path(tmp) / "mod.rs"
            owner.write_text(original, encoding="utf-8")
            self.assertEqual(complexity_budget.count_scan_backends(owner), 5)
            owner.write_text(expanded, encoding="utf-8")
            measured = complexity_budget.BUDGET.copy()
            measured["scan_backends"] = complexity_budget.count_scan_backends(owner)

        self.assertEqual(
            complexity_budget.budget_drift(measured, complexity_budget.BUDGET),
            [("scan_backends", 6, 5)],
        )

    def test_removed_measurement_cannot_leave_a_stale_budget(self) -> None:
        measured = {"engine_files": 39}
        budget = {"engine_files": 39, "engine_loc": 11_659}
        self.assertEqual(
            complexity_budget.budget_drift(measured, budget),
            [("engine_loc", None, 11_659)],
        )


class BaseComplexityRatchetTests(unittest.TestCase):
    BASE_SHA = "a" * 40
    CURRENT_SHA = "b" * 40

    def test_higher_candidate_budget_is_rejected(self) -> None:
        self.assertEqual(
            complexity_budget.budget_increases(
                {"engine_files": 40, "engine_loc": 11_659},
                {"engine_files": 39, "engine_loc": 11_659},
            ),
            [("engine_files", 40, 39)],
        )

    def test_equal_candidate_budget_is_allowed(self) -> None:
        budget = {"engine_files": 39, "engine_loc": 11_659}
        self.assertEqual(complexity_budget.budget_increases(budget, budget), [])

    def test_lower_candidate_budget_is_allowed(self) -> None:
        self.assertEqual(
            complexity_budget.budget_increases(
                {"engine_files": 38, "engine_loc": 11_000},
                {"engine_files": 39, "engine_loc": 11_659},
            ),
            [],
        )

    def test_removed_candidate_ratchet_is_rejected(self) -> None:
        self.assertEqual(
            complexity_budget.budget_increases(
                {"engine_files": 39},
                {"engine_files": 39, "engine_loc": 11_659},
            ),
            [("engine_loc", None, 11_659)],
        )

    def test_pull_request_requires_immutable_base_sha(self) -> None:
        env = {
            "GITHUB_ACTIONS": "true",
            "GITHUB_EVENT_NAME": "pull_request",
        }
        with self.assertRaisesRegex(
            complexity_budget.BaseBudgetError,
            "pull-request base is missing a full commit SHA",
        ):
            complexity_budget.resolve_ci_base(env, {"pull_request": {"base": {}}})

    def test_pull_request_and_push_derive_exact_event_commits(self) -> None:
        pull_env = {
            "GITHUB_ACTIONS": "true",
            "GITHUB_EVENT_NAME": "pull_request",
        }
        self.assertEqual(
            complexity_budget.resolve_ci_base(
                pull_env,
                {"pull_request": {"base": {"sha": self.BASE_SHA}}},
            ),
            (self.BASE_SHA, "pull-request base"),
        )

        push_env = {
            "GITHUB_ACTIONS": "true",
            "GITHUB_EVENT_NAME": "push",
        }
        self.assertEqual(
            complexity_budget.resolve_ci_base(
                push_env,
                {"before": self.BASE_SHA},
            ),
            (self.BASE_SHA, "push before"),
        )

    def test_zero_before_push_uses_first_parent_or_explicit_root_state(self) -> None:
        env = {
            "GITHUB_ACTIONS": "true",
            "GITHUB_EVENT_NAME": "push",
            "GITHUB_SHA": self.CURRENT_SHA,
        }
        event = {"before": "0" * 40}
        self.assertEqual(
            complexity_budget.resolve_ci_base(
                env,
                event,
                parent_commit_lookup=lambda _: self.BASE_SHA,
            ),
            (self.BASE_SHA, "zero-before push first parent"),
        )
        self.assertEqual(
            complexity_budget.resolve_ci_base(
                env,
                event,
                parent_commit_lookup=lambda _: None,
            ),
            (None, "initial repository root push"),
        )

    def test_trusted_main_non_change_events_have_explicit_safe_behavior(self) -> None:
        env = {
            "GITHUB_ACTIONS": "true",
            "GITHUB_EVENT_NAME": "schedule",
            "GITHUB_REF": "refs/heads/main",
        }
        self.assertEqual(
            complexity_budget.resolve_ci_base(env, {}),
            (None, "schedule on trusted main"),
        )

    def test_historical_ceiling_slack_is_tightened_to_base_measurement(self) -> None:
        trusted = complexity_budget.effective_base_budget(
            {"engine_files": 40, "engine_loc": 12_121},
            {"engine_files": 39, "engine_loc": 11_659},
        )
        self.assertEqual(
            trusted,
            {"engine_files": 39, "engine_loc": 11_659},
        )
        self.assertEqual(
            complexity_budget.budget_increases(
                {"engine_files": 39, "engine_loc": 11_660},
                trusted,
            ),
            [("engine_loc", 11_660, 11_659)],
        )

    def test_shallow_checkout_fetches_only_the_trusted_base_sha(self) -> None:
        source = 'BUDGET = {"engine_files": 39}\n'
        responses = [
            subprocess.CompletedProcess([], 128, "", "missing object"),
            subprocess.CompletedProcess([], 0, "", ""),
            subprocess.CompletedProcess([], 0, source, ""),
        ]
        with mock.patch.object(
            complexity_budget.subprocess, "run", side_effect=responses
        ) as run:
            self.assertEqual(
                complexity_budget.read_base_budget(self.BASE_SHA),
                {"engine_files": 39},
            )
        self.assertEqual(
            run.call_args_list[1].args[0],
            [
                "git",
                "fetch",
                "--no-tags",
                "--no-write-fetch-head",
                "--depth=1",
                "origin",
                self.BASE_SHA,
            ],
        )

    def test_unresolvable_required_base_fails_closed(self) -> None:
        responses = [
            subprocess.CompletedProcess([], 128, "", "missing object"),
            subprocess.CompletedProcess([], 128, "", "server refused object"),
        ]
        with mock.patch.object(
            complexity_budget.subprocess, "run", side_effect=responses
        ), self.assertRaisesRegex(
            complexity_budget.BaseBudgetError,
            "cannot fetch trusted base complexity commit",
        ):
            complexity_budget.read_base_budget(self.BASE_SHA)


    def test_base_budget_parser_never_executes_expressions(self) -> None:
        with self.assertRaisesRegex(
            complexity_budget.BaseBudgetError,
            "literal dictionary",
        ):
            complexity_budget.parse_budget_source("BUDGET = load_remote_policy()\n")


if __name__ == "__main__":
    unittest.main()
