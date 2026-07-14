"""Validated AgentRE Linux artifacts and explicit analyzer-output scoring."""

from __future__ import annotations

import json
import pathlib
from collections.abc import Mapping
from dataclasses import dataclass

from ..agentre_build import AgentREBinaryBuilder, AgentREBuildError
from ..agentre_ground_truth import AgentREGroundTruthAdapter
from ..agentre_provenance import LINUX_TASKS
from ..agentre_score import (
    decoded_c2_recovery_summary,
    score_contract_receipt,
    score_report,
)
from ..schema import RecoveryExpectation
from .agentre_recovery import AgentRERecoveryMaterializer


class AgentREBenchmarkError(RuntimeError):
    """The AgentRE artifact set or analyzer coverage is incomplete."""


@dataclass(frozen=True)
class AgentREBenchmarkTask:
    """One canonical task identity bound to its validated binary and answer key."""

    task_id: str
    binary_path: pathlib.Path
    ground_truth_path: str
    difficulty: int


class AgentREBenchmark:
    """Explicit boundary for the 13 binary recovery tasks and official rubric."""

    def __init__(
        self,
        root: str | pathlib.Path | None = None,
        *,
        builder: AgentREBinaryBuilder | None = None,
        materializer: AgentRERecoveryMaterializer | None = None,
    ):
        if builder is not None and root is not None:
            raise AgentREBenchmarkError(
                "pass either an AgentRE builder or root, not both"
            )
        self.materializer = materializer or AgentRERecoveryMaterializer()
        self.builder = builder or AgentREBinaryBuilder(
            output_dir=root,
            materializer=self.materializer,
        )

    @property
    def root(self) -> pathlib.Path:
        return self.builder.root

    def validate(self) -> dict[str, object]:
        """Validate every binary and the exact compiler-bound receipt."""

        try:
            receipt = self.builder.validate()
        except AgentREBuildError as exc:
            raise AgentREBenchmarkError(str(exc)) from exc
        binaries = receipt.get("binaries")
        if not isinstance(binaries, list) or len(binaries) != len(LINUX_TASKS):
            raise AgentREBenchmarkError(
                "AgentRE binary receipt does not cover 13 tasks"
            )
        return receipt

    def tasks(self) -> tuple[AgentREBenchmarkTask, ...]:
        """Enumerate all canonical tasks only after complete binary validation."""

        self.validate()
        return tuple(
            AgentREBenchmarkTask(
                task_id=task.task_id,
                binary_path=self.root / task.binary_name,
                ground_truth_path=task.ground_truth_path,
                difficulty=task.difficulty,
            )
            for task in LINUX_TASKS
        )

    def expectations(self) -> list[RecoveryExpectation]:
        """Return the official field-qualified rubric after binary validation."""

        self.validate()
        expectations = AgentREGroundTruthAdapter(self.materializer).expectations()
        expected_ids = {task.task_id for task in LINUX_TASKS}
        observed_ids = {expectation.sample_id for expectation in expectations}
        if len(expectations) != 149 or observed_ids != expected_ids:
            raise AgentREBenchmarkError(
                "AgentRE rubric coverage mismatch: "
                f"expected=149 fields across 13 tasks, observed={len(expectations)} "
                f"fields across {len(observed_ids)} tasks"
            )
        return expectations

    def score_analyzer_outputs(
        self, outputs: Mapping[str, Mapping[str, object]]
    ) -> dict[str, object]:
        """Score one explicit analyzer document for every canonical task."""

        self.expectations()
        if not isinstance(outputs, Mapping):
            raise AgentREBenchmarkError("AgentRE analyzer outputs must be a mapping")
        observed_outputs: dict[str, Mapping[str, object]] = {}
        for task_id, output in outputs.items():
            if not isinstance(task_id, str):
                raise AgentREBenchmarkError(
                    "AgentRE analyzer output task IDs must be strings"
                )
            if not isinstance(output, Mapping):
                raise AgentREBenchmarkError(
                    f"AgentRE analyzer output for {task_id!r} must be a mapping"
                )
            observed_outputs[task_id] = output
        expected_ids = {task.task_id for task in LINUX_TASKS}
        observed_ids = set(observed_outputs)
        if observed_ids != expected_ids:
            raise AgentREBenchmarkError(
                "AgentRE analyzer task coverage mismatch: "
                f"missing={sorted(expected_ids - observed_ids)}, "
                f"unexpected={sorted(observed_ids - expected_ids)}"
            )
        documents = self.materializer.read_pinned_texts(
            task.ground_truth_path for task in LINUX_TASKS
        )
        samples = []
        for task, (path, raw) in zip(LINUX_TASKS, documents, strict=True):
            try:
                ground_truth = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise AgentREBenchmarkError(
                    f"validated AgentRE ground truth became invalid at {path}: {exc}"
                ) from exc
            samples.append((ground_truth, observed_outputs[task.task_id], str(path)))
        report = score_report(samples)
        report["decoded_c2_recovery"] = decoded_c2_recovery_summary(samples)
        report["score_contract"] = score_contract_receipt()
        receipt = self.validate()
        report["task_selection"] = receipt["task_selection"]
        return report
