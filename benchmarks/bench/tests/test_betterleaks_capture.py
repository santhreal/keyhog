"""Betterleaks shared-workload baseline contracts."""

from __future__ import annotations

import json
import pathlib

import pytest

from bench.baseline_capture import BaselineCaptureError
from bench.betterleaks_capture import _trial, betterleaks_command
from bench.measurement import RunStats


def _stats(*, exit_code: int = 0) -> RunStats:
    return RunStats(
        wall_ms=12.5,
        peak_rss_kb=4096,
        exit_code=exit_code,
        timed_out=False,
        minor_page_faults=7,
        major_page_faults=1,
    )


@pytest.mark.parametrize(
    ("stdin", "expected_subcommand", "path_is_present"),
    [(False, "dir", True), (True, "stdin", False)],
)
def test_betterleaks_command_uses_real_route_and_disables_live_validation(
    tmp_path: pathlib.Path, stdin: bool, expected_subcommand: str, path_is_present: bool,
) -> None:
    """WHY: competitor evidence must time its real directory or stdin path without network validation noise, while retaining exact unredacted values for parity."""
    target = tmp_path / "input"
    command = betterleaks_command(tmp_path / "betterleaks", target, stdin=stdin)
    assert command[1] == expected_subcommand
    assert (str(target) in command) is path_is_present
    assert "--validation=false" in command
    assert "--redact=0" in command
    assert command[command.index("--report-format") + 1] == "json"


def test_betterleaks_trial_hashes_exact_secret_and_preserves_process_metrics() -> None:
    """WHY: a fast competitor run only counts when its measured finding identity matches the locked answer; hashing a redacted value or whole JSON object would manufacture parity."""
    secret = "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"
    trial = _trial(json.dumps([{"Secret": secret, "RuleID": "github-pat"}]), _stats())
    assert trial.finding_hashes == (
        "d7d12ecfbe43df4deab9673e592a317d66e16f7bc337d8003da5da5a08decd71",
    )
    assert trial.wall_ms == 12.5
    assert trial.peak_rss_kb == 4096
    assert trial.minor_page_faults == 7
    assert trial.major_page_faults == 1


@pytest.mark.parametrize(
    ("stdout", "exit_code", "message"),
    [("not-json", 0, "invalid JSON"), ("{}", 0, "not an array"), ("[]", 2, "exited 2")],
)
def test_betterleaks_trial_rejects_unprovable_execution(
    stdout: str, exit_code: int, message: str,
) -> None:
    """WHY: malformed output and unsuccessful processes must fail closed instead of becoming deceptively empty competitor baselines."""
    with pytest.raises(BaselineCaptureError, match=message):
        _trial(stdout, _stats(exit_code=exit_code))
