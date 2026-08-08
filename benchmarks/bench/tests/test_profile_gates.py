"""Locks overhead, stage-regression, and workflow-speed gate verdicts."""

import pathlib

import pytest

from bench.profile_artifact import parse_causal_profile
from bench.profile_gates import (
    BudgetError,
    WorkflowBudget,
    evaluate_overhead,
    evaluate_stage_regressions,
    evaluate_workflow_speed,
    load_budgets,
)
from bench.schema import CorpusInfo, RunResult, Scanner, ScannerConfig, Speed


def _profile(stages, *, run_id="run-1"):
    return parse_causal_profile(
        {
            "version": 5,
            "envelope": {
                "version": 1,
                "schema": "keyhog-profile",
                "schema_version": {"version": 1, "major": 2, "minor": 4},
            },
            "identity": {"version": 1, "run_id": run_id},
            "wall_time_ns": sum(elapsed for elapsed, _, _ in stages.values()),
            "stages": [
                {"version": 1, "stage": name, "elapsed_ns": elapsed,
                 "calls": calls, "attributed_ns": attributed}
                for name, (elapsed, calls, attributed) in stages.items()
            ],
        },
        source="test",
    )


def _row(corpus: str, wall_ms: float, *,
         config_id: str = "simd-nocache-nodaemon-full",
         available: bool = True) -> RunResult:
    config = ScannerConfig(backend="simd", cache="off", daemon="off", mode="full")
    assert config.config_id == config_id
    return RunResult(
        scanner=Scanner(name="keyhog", version="test", config=config),
        corpus=CorpusInfo(name=corpus),
        speed=Speed(wall_ms=wall_ms),
        available=available,
    )


def _budget(name="mirror", *, max_regression=1.02, min_speedup=0.0,
            stages=None) -> WorkflowBudget:
    return WorkflowBudget(
        name=name,
        max_regression_ratio=max_regression,
        min_speedup_ratio=min_speedup,
        stages=stages if stages is not None else {"decode": 1.05},
    )


# ── budget TOML loading ───────────────────────────────────────────────


_BENCHMARKS = pathlib.Path(__file__).resolve().parents[2]


def test_load_committed_budgets():
    """The committed budget file is the config the nightly gates run; it must
    always parse to these exact values."""
    budgets = load_budgets(_BENCHMARKS / "profile-gates" / "budgets.toml")
    assert budgets.overhead_max_ratio == 1.03
    assert sorted(budgets.workflows) == ["creddata", "homefield", "mirror"]
    mirror = budgets.workflows["mirror"]
    assert mirror.max_regression_ratio == 1.02
    assert mirror.min_speedup_ratio == 1.0
    assert mirror.stages["decode"] == 1.05
    assert mirror.stages["phase1-triggers"] == 1.05
    assert len(mirror.stages) == 15
    assert budgets.workflows["creddata"].stages["live-verification"] == 1.10
    assert budgets.workflows["homefield"].min_speedup_ratio == 0.0


def test_load_budgets_rejects_bad_schema_version(tmp_path):
    """A budget file from a different schema is undecidable, not a guess."""
    path = tmp_path / "b.toml"
    path.write_text('schema_version = 2\n[workflow.mirror]\n'
                    'max_regression_ratio = 1.02\n')
    with pytest.raises(BudgetError, match="schema_version"):
        load_budgets(path)


def test_load_budgets_rejects_invalid_ratios(tmp_path):
    """Ratios at or below the decidable floor would make the gate tautological
    or contradictory."""
    path = tmp_path / "b.toml"
    path.write_text('schema_version = 1\n[profiler_overhead]\nmax_ratio = 1.0\n'
                    '[workflow.mirror]\nmax_regression_ratio = 1.02\n')
    with pytest.raises(BudgetError, match="max_ratio"):
        load_budgets(path)
    path.write_text('schema_version = 1\n[workflow.mirror]\n'
                    'max_regression_ratio = 0.9\n')
    with pytest.raises(BudgetError, match="at least 1.0"):
        load_budgets(path)
    path.write_text('schema_version = 1\n[workflow.mirror]\n'
                    'max_regression_ratio = 1.02\n'
                    '[workflow.mirror.stages]\ndecode = 0.5\n')
    with pytest.raises(BudgetError, match="decode"):
        load_budgets(path)


def test_load_budgets_rejects_unknown_fields_and_empty(tmp_path):
    """Unknown budget keys hide typos that silently un-gate a workflow."""
    path = tmp_path / "b.toml"
    path.write_text('schema_version = 1\n[workflow.mirror]\n'
                    'max_regression_ratio = 1.02\nmax_regresssion = 9.0\n')
    with pytest.raises(BudgetError, match="unknown budget fields"):
        load_budgets(path)
    path.write_text("schema_version = 1\n")
    with pytest.raises(BudgetError, match="workflow"):
        load_budgets(path)


# ── profiler overhead gate ────────────────────────────────────────────


def test_overhead_gate_passes_within_budget():
    """A 3.0% overhead against a 3.1% budget passes with frozen medians and
    intervals as evidence."""
    verdict = evaluate_overhead(
        [103.0, 103.5, 102.8, 103.1, 103.3],
        [100.0, 101.0, 99.0, 100.5, 100.2],
        max_ratio=1.031,
        confidence=0.9,
        iterations=1000,
        seed=7,
    )
    assert verdict.passed
    assert verdict.violations == ()
    assert verdict.ratio == pytest.approx(103.1 / 100.2)
    assert verdict.profiled_ci.statistic == 103.1
    assert (verdict.profiled_ci.low, verdict.profiled_ci.high) == (102.8, 103.5)
    assert verdict.unprofiled_ci.statistic == 100.2
    assert (verdict.unprofiled_ci.low, verdict.unprofiled_ci.high) == (99.0, 101.0)


def test_overhead_gate_fails_over_budget():
    """A 2.97% median overhead against a 2% budget fails with the exact
    measured ratio in the message."""
    verdict = evaluate_overhead(
        [103.0, 103.5, 102.8, 103.1, 103.3],
        [100.0, 101.0, 99.0, 100.5, 100.2],
        max_ratio=1.02,
        seed=7,
    )
    assert not verdict.passed
    assert len(verdict.violations) == 1
    assert "1.0289" in verdict.violations[0]
    assert "1.0200" in verdict.violations[0]


def test_overhead_gate_rejects_parity_budget():
    """An overhead budget at or below 1.0 is undecidable: profiling is never
    free, so the gate would fail every honest run or pass a broken clock."""
    with pytest.raises(BudgetError, match="exceed 1.0"):
        evaluate_overhead([1.0], [1.0], max_ratio=1.0)


# ── stage-regression gate ─────────────────────────────────────────────


def test_stage_gate_passes_within_budgets():
    """Candidate stages at or under their ceilings produce no violations."""
    control = _profile({"decode": (1_000_000, 1, 900_000),
                        "entropy": (500_000, 1, 500_000)})
    candidate = _profile({"decode": (1_050_000, 1, 950_000),
                          "entropy": (400_000, 1, 400_000)})
    budget = _budget(stages={"decode": 1.05, "entropy": 1.05})
    assert evaluate_stage_regressions(control, candidate, budget) == []


def test_stage_gate_fails_over_budget():
    """A 12% decode regression against a 5% ceiling fails with exact ns."""
    control = _profile({"decode": (1_000_000, 1, 900_000)})
    candidate = _profile({"decode": (1_120_000, 1, 1_000_000)})
    violations = evaluate_stage_regressions(control, candidate, _budget())
    assert len(violations) == 1
    assert "decode" in violations[0]
    assert "1.1200" in violations[0]
    assert "1.0500" in violations[0]
    assert "1000000" in violations[0]
    assert "1120000" in violations[0]


def test_stage_gate_missing_stage_is_undecidable_violation():
    """A budgeted stage absent from either profile is a loud violation, never
    a skipped comparison."""
    control = _profile({"decode": (1_000_000, 1, 900_000)})
    candidate = _profile({"entropy": (500_000, 1, 500_000)})
    violations = evaluate_stage_regressions(control, candidate, _budget())
    assert len(violations) == 1
    assert "absent from the candidate profile" in violations[0]
    violations = evaluate_stage_regressions(candidate, control, _budget())
    assert len(violations) == 1
    assert "absent from the control profile" in violations[0]


def test_stage_gate_zero_control_stage():
    """A stage that took 0 ns in control and real time in candidate grew
    without bound; a still-zero candidate is fine."""
    control = _profile({"decode": (0, 0, 0)})
    candidate = _profile({"decode": (10, 1, 10)})
    violations = evaluate_stage_regressions(control, candidate, _budget())
    assert len(violations) == 1
    assert "0 ns" in violations[0]
    candidate_zero = _profile({"decode": (0, 0, 0)})
    assert evaluate_stage_regressions(control, candidate_zero, _budget()) == []


# ── workflow speed gate ───────────────────────────────────────────────


def _budgets(*workflow_budgets):
    from bench.profile_gates import GateBudgets

    return GateBudgets(overhead_max_ratio=None,
                       workflows={b.name: b for b in workflow_budgets})


def test_workflow_speed_passes_within_budget():
    """A 1% candidate slowdown against a 2% budget passes."""
    control = [_row("mirror", 100.0)]
    candidate = [_row("mirror", 101.0)]
    assert evaluate_workflow_speed(control, candidate, _budgets(_budget())) == []


def test_workflow_speed_fails_on_regression():
    """A 5% candidate slowdown against a 2% budget fails with exact walls."""
    control = [_row("mirror", 100.0)]
    candidate = [_row("mirror", 105.0)]
    violations = evaluate_workflow_speed(control, candidate, _budgets(_budget()))
    assert len(violations) == 1
    assert "mirror" in violations[0]
    assert "1.0500" in violations[0]
    assert "1.0200" in violations[0]


def test_workflow_speed_enforces_required_speedup():
    """A workflow class with a speedup floor fails when the candidate does
    not deliver it, even within the regression budget."""
    control = [_row("mirror", 100.0)]
    candidate = [_row("mirror", 99.0)]
    budget = _budget(max_regression=1.05, min_speedup=1.02)
    violations = evaluate_workflow_speed(control, candidate, _budgets(budget))
    assert len(violations) == 1
    assert "speedup" in violations[0]
    # speedup = 100/99 < 1.02
    assert "1.0101" in violations[0]


def test_workflow_speed_missing_rows_are_violations():
    """A budgeted workflow with no candidate row, or a candidate with no
    control counterpart, is undecidable, never silently skipped."""
    control = [_row("mirror", 100.0)]
    violations = evaluate_workflow_speed(control, [], _budgets(_budget()))
    assert len(violations) == 1
    assert "no candidate keyhog row" in violations[0]

    candidate = [_row("mirror", 100.0)]
    violations = evaluate_workflow_speed([], candidate, _budgets(_budget()))
    assert len(violations) == 1
    assert "no control keyhog row" in violations[0]


def test_workflow_speed_matches_on_config_id():
    """Rows pair on (corpus, config); a daemon-config candidate does not
    compare against a nodaemon control."""
    control = [_row("mirror", 100.0)]
    candidate = [
        RunResult(
            scanner=Scanner(
                name="keyhog", version="test",
                config=ScannerConfig(backend="simd", cache="off",
                                     daemon="on", mode="full"),
            ),
            corpus=CorpusInfo(name="mirror"),
            speed=Speed(wall_ms=100.0),
        )
    ]
    violations = evaluate_workflow_speed(control, candidate, _budgets(_budget()))
    assert len(violations) == 1
    assert "simd-nocache-daemon-full" in violations[0]


def test_workflow_speed_rejects_nonpositive_walls():
    """A zero wall time makes every ratio meaningless; flag it."""
    control = [_row("mirror", 100.0)]
    candidate = [_row("mirror", 0.0)]
    violations = evaluate_workflow_speed(control, candidate, _budgets(_budget()))
    assert len(violations) == 1
    assert "non-positive wall time" in violations[0]


def test_workflow_speed_unbudgeted_workflows_are_ignored():
    """Budgets opt in per workflow class; unbudgeted corpora produce no
    violations either way."""
    control = [_row("homefield", 100.0)]
    candidate = [_row("homefield", 500.0)]
    assert evaluate_workflow_speed(control, candidate, _budgets(_budget())) == []


def test_duplicate_keyhog_rows_are_rejected():
    """Two keyhog rows for one (corpus, config) make the comparison set
    ambiguous; refuse rather than pick one."""
    rows = [_row("mirror", 100.0), _row("mirror", 200.0)]
    with pytest.raises(BudgetError, match="duplicate keyhog rows"):
        evaluate_workflow_speed(rows, [], _budgets(_budget()))


def test_unprofiled_role_is_valid_overhead_evidence() -> None:
    """WHY: profiler overhead needs an explicitly unprofiled leg; relabeling it control would make stage-comparison receipts ambiguous."""
    from bench.trials import TRIAL_SET_SCHEMA_VERSION, TrialSet
    trial_set=TrialSet(schema_version=TRIAL_SET_SCHEMA_VERSION,workload="tiny",role="unprofiled",trials=())
    assert trial_set.role=="unprofiled"


def test_unprofiled_receipt_is_valid_overhead_provenance() -> None:
    """WHY: an unprofiled overhead leg needs immutable binary and trial provenance without pretending to be a stage-control profile."""
    from bench.receipts import RECEIPT_SCHEMA_VERSION, PerformanceReceipt
    receipt=PerformanceReceipt(schema_version=RECEIPT_SCHEMA_VERSION,workload="tiny",role="unprofiled",binary_sha256="a"*64,git_hash="b"*40,hostname_hash="host",os="linux",cpu="x86",trial_set_digest="c"*64,profile_artifacts=())
    assert receipt.role=="unprofiled"
