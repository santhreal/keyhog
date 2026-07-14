import copy
import hashlib
import json

import pytest

from bench.agentre_ground_truth import (
    AgentREGroundTruthAdapter,
    AgentREGroundTruthError,
)
from bench.agentre_provenance import LINUX_TASKS, PinnedArtifact
from bench.corpora.agentre_recovery import (
    AgentREMaterializationError,
    AgentRERecoveryMaterializer,
)


def standard_truth(task):
    endpoint = None if task.difficulty == 1 else f"tcp://192.0.2.{task.difficulty}:4444"
    return {
        "sample": task.task_id,
        "decoded_c2": endpoint,
        "techniques": ["T1059", f"level-{task.difficulty}"],
        "file_type": "ELF64",
        "encoded_strings": task.difficulty > 1,
        "c2_protocol": None if endpoint is None else "TCP",
    }


def all_truths():
    truths = {task.task_id: standard_truth(task) for task in LINUX_TASKS}
    bonus = truths[LINUX_TASKS[-1].task_id]
    bonus.update(
        {
            "encryption_details": {
                "algorithm": "RC4",
                "key": "gh0st_k3y_2024",
                "key_storage": "XOR mask 0xa5",
            },
            "decoded_strings": {
                "c2_url": bonus["decoded_c2"],
                "user_agent": "Mozilla/5.0",
            },
            "anti_analysis": ["ptrace", "timing check"],
        }
    )
    return truths


def materialized_corpus(tmp_path, truths, *, raw_override=None):
    payloads = {}
    for task in LINUX_TASKS:
        payloads[task.source_path] = f"source for {task.task_id}\n".encode()
        payloads[task.ground_truth_path] = json.dumps(
            truths[task.task_id], sort_keys=True
        ).encode()
    if raw_override is not None:
        path, payload = raw_override
        payloads[path] = payload
    artifacts = tuple(
        PinnedArtifact(path, hashlib.sha256(payload).hexdigest())
        for path, payload in payloads.items()
    )
    materializer = AgentRERecoveryMaterializer(
        tmp_path / "agentre-recovery", _artifacts=artifacts
    )
    materializer.materialize(lambda item: payloads[item.path])
    return materializer


def expectation_map(expectations):
    return {
        (expectation.sample_id, expectation.field): expectation.value
        for expectation in expectations
    }


def test_adapter_maps_all_pinned_tasks_and_preserves_equal_qualified_values(tmp_path):
    materializer = materialized_corpus(tmp_path, all_truths())

    expectations = AgentREGroundTruthAdapter(materializer).expectations()
    mapped = expectation_map(expectations)

    assert len(mapped) == len(expectations)
    assert {sample for sample, _field in mapped} == {
        task.task_id for task in LINUX_TASKS
    }
    bonus = LINUX_TASKS[-1].task_id
    assert mapped[(bonus, "decoded_c2")] == mapped[(bonus, "decoded_strings.c2_url")]
    assert (bonus, "decoded_c2") != (bonus, "decoded_strings.c2_url")


def test_null_endpoint_and_false_encoding_remain_explicit_expectations(tmp_path):
    materializer = materialized_corpus(tmp_path, all_truths())

    mapped = expectation_map(AgentREGroundTruthAdapter(materializer).expectations())
    first = LINUX_TASKS[0].task_id

    assert mapped[(first, "decoded_c2")] is None
    assert mapped[(first, "c2_protocol")] is None
    assert mapped[(first, "encoded_strings")] == "false"


def test_set_scored_fields_map_independently_of_source_order(tmp_path):
    left_truths = all_truths()
    right_truths = copy.deepcopy(left_truths)
    for truth in right_truths.values():
        truth["techniques"].reverse()
    right_truths[LINUX_TASKS[-1].task_id]["anti_analysis"].reverse()

    left = AgentREGroundTruthAdapter(
        materialized_corpus(tmp_path / "left", left_truths)
    ).expectations()
    right = AgentREGroundTruthAdapter(
        materialized_corpus(tmp_path / "right", right_truths)
    ).expectations()

    assert expectation_map(left) == expectation_map(right)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda value: value.pop("file_type"), "missing=\\['file_type'\\]"),
        (lambda value: value.update({"unknown": "value"}), "unknown=\\['unknown'\\]"),
        (
            lambda value: value.update({"encoded_strings": 1}),
            "encoded_strings.*boolean",
        ),
        (lambda value: value.update({"techniques": "T1059"}), "techniques.*list"),
        (lambda value: value.update({"decoded_c2": 42}), "decoded_c2.*string"),
    ],
)
def test_standard_schema_rejects_missing_unknown_and_invalid_fields(
    tmp_path, mutation, message
):
    truths = all_truths()
    mutation(truths[LINUX_TASKS[0].task_id])
    materializer = materialized_corpus(tmp_path, truths)

    with pytest.raises(AgentREGroundTruthError, match=message):
        AgentREGroundTruthAdapter(materializer).expectations()


def test_bonus_schema_rejects_unknown_nested_encryption_field(tmp_path):
    truths = all_truths()
    truths[LINUX_TASKS[-1].task_id]["encryption_details"]["iv"] = "unexpected"
    materializer = materialized_corpus(tmp_path, truths)

    with pytest.raises(AgentREGroundTruthError, match="unknown=\\['iv'\\]"):
        AgentREGroundTruthAdapter(materializer).expectations()


def test_bonus_schema_rejects_non_string_decoded_value(tmp_path):
    truths = all_truths()
    truths[LINUX_TASKS[-1].task_id]["decoded_strings"]["c2_url"] = 42
    materializer = materialized_corpus(tmp_path, truths)

    with pytest.raises(AgentREGroundTruthError, match="decoded_strings.c2_url.*string"):
        AgentREGroundTruthAdapter(materializer).expectations()


def test_duplicate_json_field_is_rejected_instead_of_silently_overridden(tmp_path):
    truths = all_truths()
    task = LINUX_TASKS[0]
    original = json.dumps(truths[task.task_id])
    duplicate = original[:-1] + ', "decoded_c2": "tcp://198.51.100.1"}'
    materializer = materialized_corpus(
        tmp_path,
        truths,
        raw_override=(task.ground_truth_path, duplicate.encode()),
    )

    with pytest.raises(AgentREGroundTruthError, match="duplicate field 'decoded_c2'"):
        AgentREGroundTruthAdapter(materializer).expectations()


def test_adapter_refuses_ground_truth_after_corpus_validation_fails(tmp_path):
    materializer = materialized_corpus(tmp_path, all_truths())
    materializer.root.chmod(0o700)

    with pytest.raises(AgentREMaterializationError, match="writable.*unsealed"):
        AgentREGroundTruthAdapter(materializer).expectations()


def test_sample_identity_must_match_the_pinned_task(tmp_path):
    truths = copy.deepcopy(all_truths())
    truths[LINUX_TASKS[3].task_id]["sample"] = "renamed"
    materializer = materialized_corpus(tmp_path, truths)

    with pytest.raises(AgentREGroundTruthError, match="sample identity mismatch"):
        AgentREGroundTruthAdapter(materializer).expectations()
