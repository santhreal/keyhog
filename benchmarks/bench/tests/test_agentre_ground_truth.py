import copy
import hashlib
import json
import pathlib

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
    truth = {
        "sample": pathlib.PurePosixPath(task.source_path).stem,
        "decoded_c2": endpoint,
        "c2_ip": None if endpoint is None else f"192.0.2.{task.difficulty}",
        "c2_port": None if endpoint is None else 4444,
        "techniques": ["T1059", f"level-{task.difficulty}"],
        "file_type": "ELF64",
        "encoded_strings": task.difficulty > 1,
        "c2_protocol": "TCP",
        "confidence": 0.9,
        "difficulty": task.difficulty,
        "description": f"Recovery fixture for {task.task_id}",
    }
    truth.update(variant_truth(task.difficulty))
    return truth


def variant_truth(difficulty):
    variants = {
        1: {"shell_path": "/bin/sh"},
        2: {
            "encryption_key": "0x22",
            "encryption_type": "xor_single_byte",
            "shell_path": "/bin/sh",
        },
        3: {"anti_analysis": ["ptrace", "delay"], "shell_path": "/bin/sh"},
        4: {
            "shellcode_details": {
                "nop_sled_size": "256-768 bytes",
                "syscall_number": 41,
                "creates_socket": True,
            }
        },
        5: {
            "encryption_type": "xor_single_byte",
            "encryption_key": "received_from_c2",
            "stages": {"stage1": "connect", "stage2": "decrypt"},
        },
        6: {
            "covert_channel": {
                "protocol": "ICMP",
                "method": "echo data",
                "beacon_interval": 5,
            }
        },
        7: {
            "dns_details": {
                "beacon_domain": "cmd.example.test",
                "exfil_format": "hex.domain",
                "encoding": "hex",
                "beacon_interval": 5,
            }
        },
        8: {
            "process_hollowing_details": {
                "target_process": "/bin/sleep",
                "injection_method": "PTRACE_POKETEXT",
                "register_control": "PTRACE_SETREGS",
                "detach_after_inject": True,
            },
            "shellcode_c2": {
                "ip_bytes": "\\x7f\\x00\\x00\\x01",
                "port_bytes": "\\x11\\x5c",
                "decoded_ip": "127.0.0.1",
                "decoded_port": 4444,
            },
        },
        9: {
            "injection_details": {
                "library_type": "shared_object",
                "activation": "constructor",
                "hooked_function": "puts",
                "hijack_method": "dlsym",
                "env_evasion": ["LD_AUDIT", "LD_PRELOAD"],
            },
            "shell_path": "/bin/sh",
        },
        10: {
            "encryption_details": {
                "claimed_type": "AES",
                "actual_type": "xor_multi_byte",
                "key": "test key",
                "key_hex": "0x1234",
                "key_length": 16,
            },
            "anti_analysis": ["env_check", "timing"],
            "obfuscation": {
                "inline_assembly": True,
                "manual_syscalls": True,
                "mmap_rwx": True,
            },
        },
        11: {
            "behavior": {
                "parent_action": "fork bomb",
                "child_action": "reverse shell",
                "dual_purpose": True,
            },
            "shell_path": "/bin/sh",
        },
        12: {
            "jit_details": {
                "memory_allocation": "mmap RWX",
                "shellcode_template": "x86-64 socket",
                "runtime_patches": {
                    "ip_offset": "0x30",
                    "port_offset": "0x34",
                    "patched_ip": "192.0.2.12",
                    "patched_port": "4444",
                },
            },
            "shell_path": "/bin/sh",
        },
        13: {
            "encryption_details": {
                "algorithm": "RC4",
                "key": "gh0st_k3y_2024",
                "key_length": 14,
                "key_storage": "XOR mask 0xa5",
                "string_table_size": 174,
            },
            "decoded_strings": {
                "os_target": "Linux",
                "infection_marker": "/tmp/marker",
                "proc_mem": "/proc/self/mem",
                "curl_binary": "curl",
                "c2_url": "tcp://192.0.2.13:4444",
                "payload_path": "/tmp/payload",
                "exec_command": "chmod +x /tmp/payload",
                "shell": "/bin/sh",
            },
            "anti_analysis": ["ptrace", "timing check"],
            "control_flow": {
                "type": "state_machine_dispatcher",
                "states": 12,
                "state_values": "non-sequential",
            },
            "behavior": {
                **{f"stage{index}": f"stage {index}" for index in range(1, 8)}
            },
        },
    }
    return variants[difficulty]


def all_truths():
    truths = {task.task_id: standard_truth(task) for task in LINUX_TASKS}
    truths[LINUX_TASKS[-1].task_id]["decoded_strings"]["c2_url"] = truths[
        LINUX_TASKS[-1].task_id
    ]["decoded_c2"]
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
    truths = all_truths()
    materializer = materialized_corpus(tmp_path, truths)

    expectations = AgentREGroundTruthAdapter(materializer).expectations()
    mapped = expectation_map(expectations)

    assert len(mapped) == len(expectations)
    assert {sample for sample, _field in mapped} == {
        task.task_id for task in LINUX_TASKS
    }
    bonus = LINUX_TASKS[-1].task_id
    assert mapped[(bonus, "decoded_c2")] == mapped[(bonus, "decoded_strings.c2_url")]
    assert (bonus, "decoded_c2") != (bonus, "decoded_strings.c2_url")


def test_upstream_metadata_is_validated_but_not_added_to_the_scoring_rubric(tmp_path):
    materializer = materialized_corpus(tmp_path, all_truths())

    mapped = expectation_map(AgentREGroundTruthAdapter(materializer).expectations())

    for task in LINUX_TASKS:
        assert (task.task_id, "sample") not in mapped
        assert (task.task_id, "description") not in mapped
        assert (task.task_id, "confidence") not in mapped
        assert (task.task_id, "difficulty") not in mapped


def test_typed_nested_values_and_duplicate_list_items_keep_distinct_fields(tmp_path):
    truths = all_truths()
    first = LINUX_TASKS[0].task_id
    truths[first]["techniques"] = ["duplicate", "duplicate"]
    materializer = materialized_corpus(tmp_path, truths)

    mapped = expectation_map(AgentREGroundTruthAdapter(materializer).expectations())
    bonus = LINUX_TASKS[-1].task_id

    assert mapped[(first, "techniques[0]")] == "duplicate"
    assert mapped[(first, "techniques[1]")] == "duplicate"
    assert mapped[(bonus, "encoded_strings")] == "true"
    assert mapped[(bonus, "encryption_details.algorithm")] == "RC4"
    assert (bonus, "control_flow.states") not in mapped


def test_null_endpoint_and_false_encoding_remain_explicit_expectations(tmp_path):
    materializer = materialized_corpus(tmp_path, all_truths())

    mapped = expectation_map(AgentREGroundTruthAdapter(materializer).expectations())
    first = LINUX_TASKS[0].task_id

    assert mapped[(first, "decoded_c2")] is None
    assert mapped[(first, "c2_protocol")] == "TCP"
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
