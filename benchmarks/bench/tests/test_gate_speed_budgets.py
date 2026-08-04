"""Locks the gate command's per-workflow-class speed budget wiring."""

import json

import pytest

from bench import gate
from bench.schema import (
    CorpusInfo,
    RunResult,
    Scanner,
    ScannerConfig,
    Speed,
    StaticRecoveryMetrics,
)


@pytest.fixture(autouse=True)
def _skip_freshness(monkeypatch):
    # The speed gate's control/candidate fixtures are synthetic; the binary
    # freshness contract is covered by test_gate.py.
    monkeypatch.setattr(gate, "_assert_keyhog_results_current", lambda rows: None)


def _row(wall_ms: float) -> RunResult:
    return RunResult(
        scanner=Scanner(
            name="keyhog",
            version="test",
            config=ScannerConfig(backend="simd", cache="off",
                                 daemon="off", mode="full"),
            executable_sha256="a" * 64,
            execution_route="in_process",
        ),
        corpus=CorpusInfo(name="mirror"),
        speed=Speed(wall_ms=wall_ms),
        available=True,
        static_recovery=StaticRecoveryMetrics(),
    )


def _write_row(directory, row: RunResult) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / row.result_filename()).write_text(
        json.dumps(row.to_json(), indent=2, sort_keys=True)
    )


def _budgets_file(tmp_path, *, max_regression=1.02) -> object:
    path = tmp_path / "budgets.toml"
    path.write_text(
        "schema_version = 1\n"
        "[workflow.mirror]\n"
        f"max_regression_ratio = {max_regression}\n"
    )
    return path


def test_gate_speed_budget_passes(tmp_path, capsys):
    """A candidate within the regression budget adds no violations and the
    gate stays green."""
    control = tmp_path / "control"
    candidate = tmp_path / "candidate"
    _write_row(control, _row(100.0))
    _write_row(candidate, _row(101.0))
    code = gate.run_gate(
        "mirror",
        [],
        results_dir=candidate,
        beat_competitors=False,
        speed_budgets=_budgets_file(tmp_path),
        speed_control_results=control,
    )
    assert code == 0
    assert "GATE PASSED" in capsys.readouterr().err


def test_gate_speed_budget_fails_on_regression(tmp_path, capsys):
    """A 10% candidate slowdown against a 2% budget fails the gate with the
    workflow class and exact ratio in the output."""
    control = tmp_path / "control"
    candidate = tmp_path / "candidate"
    _write_row(control, _row(100.0))
    _write_row(candidate, _row(110.0))
    code = gate.run_gate(
        "mirror",
        [],
        results_dir=candidate,
        beat_competitors=False,
        speed_budgets=_budgets_file(tmp_path),
        speed_control_results=control,
    )
    assert code == 1
    err = capsys.readouterr().err
    assert "GATE FAILED" in err
    assert "mirror" in err
    assert "1.1000" in err


def test_gate_speed_budget_requires_control_results(tmp_path, capsys):
    """--speed-budgets without a control result directory is undecidable,
    never a skipped check."""
    candidate = tmp_path / "candidate"
    _write_row(candidate, _row(100.0))
    code = gate.run_gate(
        "mirror",
        [],
        results_dir=candidate,
        beat_competitors=False,
        speed_budgets=_budgets_file(tmp_path),
        speed_control_results=None,
    )
    assert code == 2
    assert "--speed-control-results" in capsys.readouterr().err


def test_gate_speed_budget_missing_control_row_is_undecidable(
    tmp_path, capsys
):
    """A candidate row with no control counterpart fails the gate; an absent
    comparison is not a pass."""
    control = tmp_path / "control"
    candidate = tmp_path / "candidate"
    other = _row(100.0)
    other.corpus = CorpusInfo(name="homefield")
    _write_row(control, other)
    _write_row(candidate, _row(100.0))
    code = gate.run_gate(
        "mirror",
        [],
        results_dir=candidate,
        beat_competitors=False,
        speed_budgets=_budgets_file(tmp_path),
        speed_control_results=control,
    )
    assert code == 1
    err = capsys.readouterr().err
    assert "no control keyhog row" in err
