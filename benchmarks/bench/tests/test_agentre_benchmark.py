import hashlib
import json
import pathlib
import struct

import pytest

from bench.agentre_build import AgentREBinaryBuilder
from bench.agentre_provenance import LINUX_TASKS
from bench.corpora.agentre import AgentREBenchmark, AgentREBenchmarkError
from bench.corpora.agentre_recovery import AgentREMaterializationError


class FakeSourceMaterializer:
    def read_pinned_texts(self, paths):
        return [
            (pathlib.Path(path), "int main(void) { return 0; }\n") for path in paths
        ]


def fake_elf(name: str, *, shared: bool) -> bytes:
    payload = bytearray(64)
    payload[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HH", payload, 16, 3 if shared else 2, 62)
    payload.extend(name.encode())
    return bytes(payload)


def fake_inventory():
    return {
        task.binary_name: hashlib.sha256(
            fake_elf(task.binary_name, shared=task.difficulty == 9)
        ).hexdigest()
        for task in LINUX_TASKS
    }


def built_benchmark(tmp_path):
    def runner(_argv, output, _timeout):
        output.write_bytes(
            fake_elf(output.name, shared=output.name.startswith("level9_"))
        )

    builder = AgentREBinaryBuilder(
        tmp_path / "agentre-binaries",
        materializer=FakeSourceMaterializer(),
        _runner=runner,
        _expected=fake_inventory(),
    )
    builder.build()
    return AgentREBenchmark(builder=builder)


def official_outputs(benchmark):
    documents = benchmark.materializer.read_pinned_texts(
        task.ground_truth_path for task in LINUX_TASKS
    )
    return {
        task.task_id: json.loads(raw)
        for task, (_path, raw) in zip(LINUX_TASKS, documents, strict=True)
    }


def test_enumerates_exact_canonical_tasks_after_validation(tmp_path):
    benchmark = built_benchmark(tmp_path)

    tasks = benchmark.tasks()

    assert [task.task_id for task in tasks] == [task.task_id for task in LINUX_TASKS]
    assert [task.binary_path.name for task in tasks] == [
        task.binary_name for task in LINUX_TASKS
    ]
    assert [task.ground_truth_path for task in tasks] == [
        task.ground_truth_path for task in LINUX_TASKS
    ]
    assert [task.difficulty for task in tasks] == list(range(1, 14))
    assert all(task.binary_path.parent == benchmark.root for task in tasks)


@pytest.mark.parametrize(
    "mutation", ["absent", "writable", "extra", "digest", "symlink"]
)
def test_task_enumeration_fails_closed_on_binary_integrity_failure(tmp_path, mutation):
    benchmark = built_benchmark(tmp_path)
    root = benchmark.root
    target = root / LINUX_TASKS[0].binary_name
    if mutation == "absent":
        root.chmod(0o700)
        for child in root.iterdir():
            child.chmod(0o600)
            child.unlink()
        root.rmdir()
    elif mutation == "writable":
        root.chmod(0o700)
    elif mutation == "extra":
        root.chmod(0o700)
        extra = root / "unexpected"
        extra.write_bytes(b"extra")
        extra.chmod(0o400)
        root.chmod(0o500)
    elif mutation == "digest":
        root.chmod(0o700)
        target.chmod(0o600)
        target.write_bytes(fake_elf("replacement", shared=False))
        target.chmod(0o400)
        root.chmod(0o500)
    else:
        external = tmp_path / "external"
        external.write_bytes(fake_elf(target.name, shared=False))
        root.chmod(0o700)
        target.unlink()
        target.symlink_to(external)
        root.chmod(0o500)

    with pytest.raises(AgentREBenchmarkError):
        benchmark.tasks()


def test_official_rubric_scores_complete_exact_outputs(tmp_path):
    benchmark = built_benchmark(tmp_path)
    try:
        expectations = benchmark.expectations()
        outputs = official_outputs(benchmark)
    except AgentREMaterializationError as exc:
        pytest.skip(f"validated official AgentRE corpus is unavailable: {exc}")

    report = benchmark.score_analyzer_outputs(outputs)

    assert len(expectations) == 149
    assert len({expectation.sample_id for expectation in expectations}) == 13
    assert report["summary"]["standard_samples"] == 12
    assert report["summary"]["main_score"] == 1.0
    assert report["summary"]["bonus_score"] == 0.95
    assert report["summary"]["total_score"] == 1.95
    assert report["decoded_c2_recovery"] == {
        "schema": "agentre-decoded-c2-recovery-v1",
        "positive": {"exact": 11, "host_partial": 0, "missed": 0, "total": 11},
        "negative": {"absent": 2, "spurious": 0, "total": 2},
    }
    assert report["score_contract"] == {
        "schema": "agentre-score-contract-v1",
        "declared": {"main_max": 1.0, "bonus_max": 1.0, "total_max": 2.0},
        "attainable": {"main_max": 1.0, "bonus_max": 0.95, "total_max": 1.95},
        "consistent": False,
    }


def test_missing_and_unexpected_analyzer_tasks_fail_complete_coverage(tmp_path):
    benchmark = built_benchmark(tmp_path)
    try:
        outputs = official_outputs(benchmark)
    except AgentREMaterializationError as exc:
        pytest.skip(f"validated official AgentRE corpus is unavailable: {exc}")
    missing_id = LINUX_TASKS[0].task_id
    outputs.pop(missing_id)
    outputs["unexpected"] = {}

    with pytest.raises(
        AgentREBenchmarkError,
        match=rf"task coverage mismatch: missing=\['{missing_id}'\].*unexpected",
    ):
        benchmark.score_analyzer_outputs(outputs)


@pytest.mark.parametrize(
    ("outputs", "message"),
    [
        ([], "outputs must be a mapping"),
        ({1: {}}, "task IDs must be strings"),
        ({task.task_id: [] for task in LINUX_TASKS}, "must be a mapping"),
    ],
)
def test_analyzer_output_boundary_rejects_non_mapping_documents(
    tmp_path, outputs, message
):
    benchmark = built_benchmark(tmp_path)
    try:
        benchmark.materializer.validate()
    except AgentREMaterializationError as exc:
        pytest.skip(f"validated official AgentRE corpus is unavailable: {exc}")

    with pytest.raises(AgentREBenchmarkError, match=message):
        benchmark.score_analyzer_outputs(outputs)


def test_scoring_revalidates_binary_artifacts_before_returning(tmp_path):
    benchmark = built_benchmark(tmp_path)
    try:
        outputs = official_outputs(benchmark)
    except AgentREMaterializationError as exc:
        pytest.skip(f"validated official AgentRE corpus is unavailable: {exc}")
    builder = benchmark.builder

    class ReplaceOnSecondValidation:
        root = builder.root
        calls = 0

        def validate(self):
            self.calls += 1
            if self.calls == 2:
                target = self.root / LINUX_TASKS[0].binary_name
                self.root.chmod(0o700)
                target.chmod(0o600)
                target.write_bytes(fake_elf("replacement", shared=False))
                target.chmod(0o400)
                self.root.chmod(0o500)
            return builder.validate()

    guarded = AgentREBenchmark(
        builder=ReplaceOnSecondValidation(), materializer=benchmark.materializer
    )

    with pytest.raises(AgentREBenchmarkError, match="binary digest mismatch"):
        guarded.score_analyzer_outputs(outputs)
