"""Strict AgentRE ground-truth parsing into field-qualified expectations."""

from __future__ import annotations

import json
import math
import pathlib
from collections.abc import Iterable

from .agentre_provenance import AgentRETask, LINUX_TASKS
from .corpora.agentre_recovery import AgentRERecoveryMaterializer
from .schema import RecoveryExpectation

COMMON_SCHEMA = {
    "sample": "string",
    "file_type": "string",
    "encoded_strings": "bool",
    "decoded_c2": "optional_string",
    "c2_ip": "optional_string",
    "c2_port": "optional_int",
    "c2_protocol": "string",
    "techniques": ("list", "string"),
    "confidence": "number",
    "difficulty": "int",
    "description": "string",
}
LEVEL_SCHEMA = {
    1: {"shell_path": "string"},
    2: {
        "encryption_key": "string",
        "encryption_type": "string",
        "shell_path": "string",
    },
    3: {"anti_analysis": ("list", "string"), "shell_path": "string"},
    4: {
        "shellcode_details": {
            "nop_sled_size": "string",
            "syscall_number": "int",
            "creates_socket": "bool",
        }
    },
    5: {
        "encryption_type": "string",
        "encryption_key": "string",
        "stages": {"stage1": "string", "stage2": "string"},
    },
    6: {
        "covert_channel": {
            "protocol": "string",
            "method": "string",
            "beacon_interval": "int",
        }
    },
    7: {
        "dns_details": {
            "beacon_domain": "string",
            "exfil_format": "string",
            "encoding": "string",
            "beacon_interval": "int",
        }
    },
    8: {
        "process_hollowing_details": {
            "target_process": "string",
            "injection_method": "string",
            "register_control": "string",
            "detach_after_inject": "bool",
        },
        "shellcode_c2": {
            "ip_bytes": "string",
            "port_bytes": "string",
            "decoded_ip": "string",
            "decoded_port": "int",
        },
    },
    9: {
        "injection_details": {
            "library_type": "string",
            "activation": "string",
            "hooked_function": "string",
            "hijack_method": "string",
            "env_evasion": ("list", "string"),
        },
        "shell_path": "string",
    },
    10: {
        "encryption_details": {
            "claimed_type": "string",
            "actual_type": "string",
            "key": "string",
            "key_hex": "string",
            "key_length": "int",
        },
        "anti_analysis": ("list", "string"),
        "obfuscation": {
            "inline_assembly": "bool",
            "manual_syscalls": "bool",
            "mmap_rwx": "bool",
        },
    },
    11: {
        "behavior": {
            "parent_action": "string",
            "child_action": "string",
            "dual_purpose": "bool",
        },
        "shell_path": "string",
    },
    12: {
        "jit_details": {
            "memory_allocation": "string",
            "shellcode_template": "string",
            "runtime_patches": {
                "ip_offset": "string",
                "port_offset": "string",
                "patched_ip": "string",
                "patched_port": "string",
            },
        },
        "shell_path": "string",
    },
    13: {
        "encryption_details": {
            "algorithm": "string",
            "key": "string",
            "key_length": "int",
            "key_storage": "string",
            "string_table_size": "int",
        },
        "anti_analysis": ("list", "string"),
        "control_flow": {
            "type": "string",
            "states": "int",
            "state_values": "string",
        },
        "decoded_strings": {
            "os_target": "string",
            "infection_marker": "string",
            "proc_mem": "string",
            "curl_binary": "string",
            "c2_url": "string",
            "payload_path": "string",
            "exec_command": "string",
            "shell": "string",
        },
        "behavior": {
            **{f"stage{index}": "string" for index in range(1, 8)},
        },
    },
}
STANDARD_RUBRIC_FIELDS = (
    "decoded_c2",
    "techniques",
    "file_type",
    "encoded_strings",
    "c2_protocol",
)
BONUS_ENCRYPTION_FIELDS = ("algorithm", "key", "key_storage")


class AgentREGroundTruthError(ValueError):
    """A validated corpus contains ground truth outside the pinned contract."""


def _json_without_duplicate_keys(payload: str, *, path: pathlib.Path) -> object:
    def object_pairs(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise AgentREGroundTruthError(
                    f"AgentRE ground truth contains duplicate field {key!r}: {path}"
                )
            value[key] = item
        return value

    try:
        return json.loads(payload, object_pairs_hook=object_pairs)
    except AgentREGroundTruthError:
        raise
    except json.JSONDecodeError as exc:
        raise AgentREGroundTruthError(
            f"AgentRE ground truth is invalid JSON at {path}: {exc}"
        ) from exc


def _require_exact_fields(
    value: dict,
    expected: frozenset[str] | set[str],
    *,
    context: str,
) -> None:
    observed = set(value)
    if observed != expected:
        missing = sorted(expected - observed)
        unknown = sorted(observed - expected)
        raise AgentREGroundTruthError(
            f"AgentRE {context} fields do not match the pinned schema: "
            f"missing={missing}, unknown={unknown}"
        )


def _require_string(value: object, *, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise AgentREGroundTruthError(
            f"AgentRE field {field!r} must be a non-empty string"
        )
    return value


def _append_typed_value(
    output: list[RecoveryExpectation] | None,
    *,
    sample_id: str,
    field: str,
    value: object,
    schema: object,
) -> None:
    if isinstance(schema, dict):
        if not isinstance(value, dict):
            raise AgentREGroundTruthError(f"AgentRE field {field!r} must be an object")
        _require_exact_fields(value, set(schema), context=field)
        for name in sorted(schema):
            _append_typed_value(
                output,
                sample_id=sample_id,
                field=f"{field}.{name}",
                value=value[name],
                schema=schema[name],
            )
        return
    if isinstance(schema, tuple) and schema[0] == "list":
        if not isinstance(value, list):
            raise AgentREGroundTruthError(f"AgentRE field {field!r} must be a list")
        ordered = sorted(
            value,
            key=lambda item: json.dumps(
                item, sort_keys=True, separators=(",", ":"), ensure_ascii=False
            ),
        )
        for index, item in enumerate(ordered):
            _append_typed_value(
                output,
                sample_id=sample_id,
                field=f"{field}[{index}]",
                value=item,
                schema=schema[1],
            )
        return

    normalized: str | None
    if schema == "string":
        normalized = _require_string(value, field=field)
    elif schema == "optional_string":
        normalized = None if value is None else _require_string(value, field=field)
    elif schema == "bool":
        if not isinstance(value, bool):
            raise AgentREGroundTruthError(f"AgentRE field {field!r} must be a boolean")
        normalized = "true" if value else "false"
    elif schema in {"int", "optional_int"}:
        if value is None and schema == "optional_int":
            normalized = None
        elif not isinstance(value, int) or isinstance(value, bool):
            raise AgentREGroundTruthError(f"AgentRE field {field!r} must be an integer")
        else:
            normalized = str(value)
    elif schema == "number":
        if (
            not isinstance(value, (int, float))
            or isinstance(value, bool)
            or not math.isfinite(value)
        ):
            raise AgentREGroundTruthError(
                f"AgentRE field {field!r} must be a finite number"
            )
        normalized = json.dumps(value, allow_nan=False)
    else:
        raise AgentREGroundTruthError(
            f"AgentRE field {field!r} has no pinned schema type"
        )
    if output is not None:
        output.append(RecoveryExpectation(sample_id, field, normalized))


def _parse_task(
    task: AgentRETask,
    path: pathlib.Path,
    raw: str,
) -> list[RecoveryExpectation]:
    value = _json_without_duplicate_keys(raw, path=path)
    if not isinstance(value, dict):
        raise AgentREGroundTruthError(f"AgentRE ground truth must be an object: {path}")

    variant_schema = LEVEL_SCHEMA.get(task.difficulty)
    if variant_schema is None:
        raise AgentREGroundTruthError(
            f"AgentRE task difficulty has no pinned schema: {task.difficulty}"
        )
    schema = {**COMMON_SCHEMA, **variant_schema}
    _require_exact_fields(value, set(schema), context=f"task {task.task_id!r}")
    sample = _require_string(value["sample"], field="sample")
    expected_sample = pathlib.PurePosixPath(task.source_path).stem
    if sample != expected_sample:
        raise AgentREGroundTruthError(
            f"AgentRE sample identity mismatch for {task.task_id!r}: "
            f"expected {expected_sample!r}, observed {sample!r}"
        )
    difficulty = value["difficulty"]
    if (
        not isinstance(difficulty, int)
        or isinstance(difficulty, bool)
        or difficulty != task.difficulty
    ):
        raise AgentREGroundTruthError(
            f"AgentRE difficulty mismatch for {task.task_id!r}: {difficulty!r}"
        )

    for field in sorted(schema):
        _append_typed_value(
            None,
            sample_id=task.task_id,
            field=field,
            value=value[field],
            schema=schema[field],
        )

    output: list[RecoveryExpectation] = []
    for field in STANDARD_RUBRIC_FIELDS:
        _append_typed_value(
            output,
            sample_id=task.task_id,
            field=field,
            value=value[field],
            schema=schema[field],
        )
    if task.difficulty == 13:
        encryption = value["encryption_details"]
        encryption_schema = schema["encryption_details"]
        for name in BONUS_ENCRYPTION_FIELDS:
            _append_typed_value(
                output,
                sample_id=task.task_id,
                field=f"encryption_details.{name}",
                value=encryption[name],
                schema=encryption_schema[name],
            )
        for field in ("decoded_strings", "anti_analysis"):
            _append_typed_value(
                output,
                sample_id=task.task_id,
                field=field,
                value=value[field],
                schema=schema[field],
            )
    return output


class AgentREGroundTruthAdapter:
    """Read all 13 pinned task answers only after corpus validation succeeds."""

    def __init__(
        self,
        materializer: AgentRERecoveryMaterializer,
        *,
        _tasks: Iterable[AgentRETask] | None = None,
    ):
        self.materializer = materializer
        self._tasks = tuple(LINUX_TASKS if _tasks is None else _tasks)
        if self._tasks != LINUX_TASKS:
            raise AgentREGroundTruthError(
                "AgentRE ground-truth adapter requires the 13 pinned Linux tasks"
            )

    def expectations(self) -> list[RecoveryExpectation]:
        payloads = self.materializer.read_pinned_texts(
            task.ground_truth_path for task in self._tasks
        )
        output: list[RecoveryExpectation] = []
        for task, (path, payload) in zip(self._tasks, payloads, strict=True):
            output.extend(_parse_task(task, path, payload))
        return output
