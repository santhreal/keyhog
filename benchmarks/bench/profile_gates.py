"""Profiler overhead, stage-regression, and workflow-speed gates.

Three independent verdicts, all pure and deterministic:

* profiler overhead: profiled vs unprofiled wall times of the same workload
  must stay within a configured ratio, so profiler cost is gated separately
  from scanner performance;
* stage regressions: candidate causal profile stage latencies are compared
  against the control profile with per-workload, per-stage budget ceilings;
* workflow speed: candidate end-to-end wall times are compared against the
  control per workflow class with regression and speedup budgets.

Budgets live in TOML; see ``benchmarks/profile-gates/budgets.toml``.
"""

from __future__ import annotations

import pathlib
import tomllib
from dataclasses import dataclass
from typing import Sequence

from .profile_artifact import CausalProfile
from .robust_stats import BootstrapCI, bootstrap_median_ci, median_ratio
from .schema import RunResult

BUDGETS_SCHEMA_VERSION = 1


class BudgetError(ValueError):
    """A budget configuration that is malformed or undecidable."""


@dataclass(frozen=True)
class WorkflowBudget:
    """Speed and stage budgets for one workflow class (one corpus)."""

    name: str
    max_regression_ratio: float
    min_speedup_ratio: float
    stages: dict[str, float]


@dataclass(frozen=True)
class GateBudgets:
    """The full per-workload budget configuration."""

    overhead_max_ratio: float | None
    workflows: dict[str, WorkflowBudget]


def _positive_float(value: object, field_name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise BudgetError(f"budget {field_name} must be a number, got {value!r}")
    result = float(value)
    if not result > 0.0:
        raise BudgetError(f"budget {field_name} must be positive, got {result!r}")
    return result


def load_budgets(path: str | pathlib.Path) -> GateBudgets:
    """Load and strictly validate one budget TOML file."""
    budget_path = pathlib.Path(path)
    try:
        data = tomllib.loads(budget_path.read_text())
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise BudgetError(f"cannot load budget file {budget_path}: {exc}") from exc
    if not isinstance(data, dict):
        raise BudgetError(f"budget file {budget_path} must be a TOML table")
    schema_version = data.get("schema_version")
    if schema_version != BUDGETS_SCHEMA_VERSION:
        raise BudgetError(
            f"budget file {budget_path} schema_version must be "
            f"{BUDGETS_SCHEMA_VERSION}, got {schema_version!r}"
        )
    overhead_max_ratio: float | None = None
    overhead = data.get("profiler_overhead")
    if overhead is not None:
        if not isinstance(overhead, dict):
            raise BudgetError("profiler_overhead must be a TOML table")
        overhead_max_ratio = _positive_float(
            overhead.get("max_ratio"), "profiler_overhead.max_ratio"
        )
        if overhead_max_ratio <= 1.0:
            raise BudgetError(
                "profiler_overhead.max_ratio must exceed 1.0; profiling is "
                "never free, so a budget at or below parity is undecidable"
            )
    raw_workflows = data.get("workflow")
    if not isinstance(raw_workflows, dict) or not raw_workflows:
        raise BudgetError(
            f"budget file {budget_path} must declare at least one [workflow.*] table"
        )
    workflows: dict[str, WorkflowBudget] = {}
    for name, raw in sorted(raw_workflows.items()):
        if not isinstance(raw, dict):
            raise BudgetError(f"workflow {name!r} must be a TOML table")
        unknown = set(raw) - {"max_regression_ratio", "min_speedup_ratio", "stages"}
        if unknown:
            raise BudgetError(
                f"workflow {name!r} has unknown budget fields: {sorted(unknown)}"
            )
        max_regression = _positive_float(
            raw.get("max_regression_ratio"), f"workflow.{name}.max_regression_ratio"
        )
        if max_regression < 1.0:
            raise BudgetError(
                f"workflow {name!r} max_regression_ratio must be at least 1.0"
            )
        min_speedup = float(raw.get("min_speedup_ratio", 0.0))
        if not min_speedup >= 0.0:
            raise BudgetError(
                f"workflow {name!r} min_speedup_ratio must be non-negative"
            )
        raw_stages = raw.get("stages", {})
        if not isinstance(raw_stages, dict):
            raise BudgetError(f"workflow {name!r} stages must be a TOML table")
        stages: dict[str, float] = {}
        for stage, ceiling in sorted(raw_stages.items()):
            ratio = _positive_float(ceiling, f"workflow.{name}.stages.{stage}")
            if ratio < 1.0:
                raise BudgetError(
                    f"workflow {name!r} stage {stage!r} budget must be at least "
                    "1.0; a candidate stage cannot be mandated faster"
                )
            stages[stage] = ratio
        workflows[name] = WorkflowBudget(
            name=name,
            max_regression_ratio=max_regression,
            min_speedup_ratio=min_speedup,
            stages=stages,
        )
    return GateBudgets(
        overhead_max_ratio=overhead_max_ratio,
        workflows=workflows,
    )


@dataclass(frozen=True)
class OverheadVerdict:
    """Profiled-vs-unprofiled comparison for one workload."""

    passed: bool
    ratio: float
    profiled_ci: BootstrapCI
    unprofiled_ci: BootstrapCI
    violations: tuple[str, ...]


def evaluate_overhead(
    profiled_walls: Sequence[float],
    unprofiled_walls: Sequence[float],
    *,
    max_ratio: float,
    confidence: float = 0.95,
    iterations: int = 2000,
    seed: int = 0,
) -> OverheadVerdict:
    """Fail when profiling overhead exceeds ``max_ratio`` of unprofiled wall.

    The verdict compares the ratio of medians and carries both bootstrap
    intervals as evidence, so a noisy host shows up in the receipt instead of
    flipping the gate silently.
    """
    if not max_ratio > 1.0:
        raise BudgetError(
            f"overhead max_ratio must exceed 1.0, got {max_ratio!r}"
        )
    profiled_ci = bootstrap_median_ci(
        profiled_walls, confidence=confidence, iterations=iterations, seed=seed
    )
    unprofiled_ci = bootstrap_median_ci(
        unprofiled_walls, confidence=confidence, iterations=iterations, seed=seed
    )
    ratio = median_ratio(unprofiled_ci.statistic, profiled_ci.statistic)
    violations: list[str] = []
    if ratio > max_ratio:
        violations.append(
            f"profiler overhead ratio {ratio:.4f} exceeds budget "
            f"{max_ratio:.4f} (profiled median {profiled_ci.statistic:.3f} ms "
            f"vs unprofiled {unprofiled_ci.statistic:.3f} ms)"
        )
    return OverheadVerdict(
        passed=not violations,
        ratio=ratio,
        profiled_ci=profiled_ci,
        unprofiled_ci=unprofiled_ci,
        violations=tuple(violations),
    )


def evaluate_stage_regressions(
    control: CausalProfile,
    candidate: CausalProfile,
    budget: WorkflowBudget,
) -> list[str]:
    """Per-stage latency violations of the candidate vs the control profile.

    A budgeted stage missing from either profile is a violation: the gate is
    undecidable for that stage and must say so, never skip it silently.
    """
    control_stages = control.stage_map()
    candidate_stages = candidate.stage_map()
    violations: list[str] = []
    for stage, ceiling in sorted(budget.stages.items()):
        ctrl = control_stages.get(stage)
        cand = candidate_stages.get(stage)
        if ctrl is None:
            violations.append(
                f"stage {stage!r} budgeted for workflow {budget.name!r} is "
                "absent from the control profile; the comparison is undecidable"
            )
            continue
        if cand is None:
            violations.append(
                f"stage {stage!r} budgeted for workflow {budget.name!r} is "
                "absent from the candidate profile; the comparison is undecidable"
            )
            continue
        if ctrl.elapsed_ns == 0:
            if cand.elapsed_ns > 0:
                violations.append(
                    f"stage {stage!r} grew from 0 ns to {cand.elapsed_ns} ns "
                    f"against an infinite ratio ceiling {ceiling:.4f}"
                )
            continue
        ratio = cand.elapsed_ns / ctrl.elapsed_ns
        if ratio > ceiling:
            violations.append(
                f"stage {stage!r} latency ratio {ratio:.4f} exceeds budget "
                f"{ceiling:.4f} for workflow {budget.name!r} "
                f"(control {ctrl.elapsed_ns} ns, candidate {cand.elapsed_ns} ns)"
            )
    return violations


def _keyhog_rows(rows: Sequence[RunResult]) -> dict[tuple[str, str], RunResult]:
    out: dict[tuple[str, str], RunResult] = {}
    for row in rows:
        if row.scanner.name != "keyhog" or not row.available:
            continue
        key = (row.corpus.name, row.scanner.config_id)
        if key in out:
            raise BudgetError(
                f"duplicate keyhog rows for workflow {key[0]!r} config "
                f"{key[1]!r}; the comparison set must be unambiguous"
            )
        out[key] = row
    return out


def evaluate_workflow_speed(
    control_rows: Sequence[RunResult],
    candidate_rows: Sequence[RunResult],
    budgets: GateBudgets,
) -> list[str]:
    """Per-workflow-class end-to-end speed violations of candidate vs control.

    Rows pair on (corpus, config_id). Budgets apply to the workflow classes
    the comparison sets actually cover: a budgeted workflow with a control
    row but no candidate row, and any candidate row with no control
    counterpart, is a violation rather than a skipped comparison.
    """
    control = _keyhog_rows(control_rows)
    candidate = _keyhog_rows(candidate_rows)
    violations: list[str] = []
    for workflow in sorted(budgets.workflows):
        has_control = any(corpus == workflow for corpus, _ in control)
        has_candidate = any(corpus == workflow for corpus, _ in candidate)
        if has_control and not has_candidate:
            violations.append(
                f"workflow {workflow!r} has a speed budget and a control row "
                "but no candidate keyhog row; the gate is undecidable"
            )
    for (corpus, config_id), cand_row in sorted(candidate.items()):
        budget = budgets.workflows.get(corpus)
        if budget is None:
            continue
        ctrl_row = control.get((corpus, config_id))
        if ctrl_row is None:
            violations.append(
                f"workflow {corpus!r} config {config_id!r} has no control "
                "keyhog row; the comparison is undecidable"
            )
            continue
        ctrl_wall = ctrl_row.speed.wall_ms
        cand_wall = cand_row.speed.wall_ms
        label = f"workflow {corpus!r} config {config_id!r}"
        if ctrl_wall <= 0.0 or cand_wall <= 0.0:
            violations.append(
                f"{label} has a non-positive wall time "
                f"(control {ctrl_wall}, candidate {cand_wall}); the "
                "comparison is undecidable"
            )
            continue
        ratio = cand_wall / ctrl_wall
        if ratio > budget.max_regression_ratio:
            violations.append(
                f"{label} wall ratio {ratio:.4f} exceeds regression budget "
                f"{budget.max_regression_ratio:.4f} (control "
                f"{ctrl_wall:.2f} ms, candidate {cand_wall:.2f} ms)"
            )
        speedup = ctrl_wall / cand_wall
        if speedup < budget.min_speedup_ratio:
            violations.append(
                f"{label} speedup {speedup:.4f} is below the required "
                f"{budget.min_speedup_ratio:.4f} (control {ctrl_wall:.2f} ms, "
                f"candidate {cand_wall:.2f} ms)"
            )
    return violations
