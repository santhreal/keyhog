"""Strict AgentRE ground-truth parsing into field-qualified expectations."""

from __future__ import annotations

import json
import os
import pathlib
import stat
from collections.abc import Iterable

from .agentre_provenance import AgentRETask, LINUX_TASKS
from .corpora.agentre_recovery import (
    MAX_ARTIFACT_BYTES,
    AgentRERecoveryMaterializer,
)
from .schema import RecoveryExpectation

STANDARD_FIELDS = frozenset(
    {
        "sample",
        "decoded_c2",
        "techniques",
        "file_type",
        "encoded_strings",
        "c2_protocol",
    }
)
BONUS_FIELDS = STANDARD_FIELDS | {
    "encryption_details",
    "decoded_strings",
    "anti_analysis",
}
ENCRYPTION_FIELDS = frozenset({"algorithm", "key", "key_storage"})


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


def _require_optional_string(value: object, *, field: str) -> str | None:
    if value is None:
        return None
    return _require_string(value, field=field)


def _require_string_list(value: object, *, field: str) -> list[str]:
    if not isinstance(value, list):
        raise AgentREGroundTruthError(f"AgentRE field {field!r} must be a list")
    items = [
        _require_string(item, field=f"{field}[{index}]")
        for index, item in enumerate(value)
    ]
    if len(items) != len(set(items)):
        raise AgentREGroundTruthError(
            f"AgentRE field {field!r} must not contain duplicate values"
        )
    return items


def _append_scalar(
    output: list[RecoveryExpectation],
    *,
    sample_id: str,
    field: str,
    value: str | None,
) -> None:
    output.append(RecoveryExpectation(sample_id, field, value))


def _append_string_list(
    output: list[RecoveryExpectation],
    *,
    sample_id: str,
    field: str,
    values: list[str],
) -> None:
    for index, value in enumerate(sorted(values)):
        _append_scalar(
            output,
            sample_id=sample_id,
            field=f"{field}[{index}]",
            value=value,
        )


def _read_verified_ground_truth(
    materializer: AgentRERecoveryMaterializer,
    task: AgentRETask,
) -> tuple[pathlib.Path, str]:
    artifact = materializer._expected_files.get(task.ground_truth_path)
    if artifact is None:
        raise AgentREGroundTruthError(
            f"validated AgentRE corpus does not pin {task.ground_truth_path}"
        )
    path = materializer.root.joinpath(
        *pathlib.PurePosixPath(task.ground_truth_path).parts
    )
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise AgentREGroundTruthError(
            f"could not read pinned AgentRE ground truth {path}: {exc}"
        ) from exc
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or opened.st_mode & 0o333:
            raise AgentREGroundTruthError(
                f"AgentRE ground truth is not a sealed regular file: {path}"
            )
        if opened.st_size > MAX_ARTIFACT_BYTES:
            raise AgentREGroundTruthError(
                f"AgentRE ground truth exceeds the size limit: {path}"
            )
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            payload = handle.read(MAX_ARTIFACT_BYTES + 1)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if len(payload) > MAX_ARTIFACT_BYTES:
        raise AgentREGroundTruthError(
            f"AgentRE ground truth exceeds the size limit: {path}"
        )
    try:
        artifact.verify(payload)
    except ValueError as exc:
        raise AgentREGroundTruthError(str(exc)) from exc
    try:
        return path, payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise AgentREGroundTruthError(
            f"AgentRE ground truth is not valid UTF-8 at {path}: {exc}"
        ) from exc


def _parse_task(
    task: AgentRETask,
    path: pathlib.Path,
    raw: str,
) -> list[RecoveryExpectation]:
    value = _json_without_duplicate_keys(raw, path=path)
    if not isinstance(value, dict):
        raise AgentREGroundTruthError(f"AgentRE ground truth must be an object: {path}")

    expected_fields = BONUS_FIELDS if task.difficulty == 13 else STANDARD_FIELDS
    _require_exact_fields(value, expected_fields, context=f"task {task.task_id!r}")
    sample = _require_string(value["sample"], field="sample")
    if sample != task.task_id:
        raise AgentREGroundTruthError(
            f"AgentRE sample identity mismatch for {task.task_id!r}: {sample!r}"
        )

    decoded_c2 = _require_optional_string(value["decoded_c2"], field="decoded_c2")
    file_type = _require_string(value["file_type"], field="file_type")
    encoded_strings = value["encoded_strings"]
    if not isinstance(encoded_strings, bool):
        raise AgentREGroundTruthError(
            "AgentRE field 'encoded_strings' must be a boolean"
        )
    c2_protocol = _require_optional_string(value["c2_protocol"], field="c2_protocol")
    techniques = _require_string_list(value["techniques"], field="techniques")

    output: list[RecoveryExpectation] = []
    _append_scalar(output, sample_id=task.task_id, field="decoded_c2", value=decoded_c2)
    _append_scalar(output, sample_id=task.task_id, field="file_type", value=file_type)
    _append_scalar(
        output,
        sample_id=task.task_id,
        field="encoded_strings",
        value="true" if encoded_strings else "false",
    )
    _append_scalar(
        output,
        sample_id=task.task_id,
        field="c2_protocol",
        value=c2_protocol,
    )
    _append_string_list(
        output,
        sample_id=task.task_id,
        field="techniques",
        values=techniques,
    )

    if task.difficulty != 13:
        return output

    encryption = value["encryption_details"]
    if not isinstance(encryption, dict):
        raise AgentREGroundTruthError(
            "AgentRE field 'encryption_details' must be an object"
        )
    _require_exact_fields(
        encryption,
        ENCRYPTION_FIELDS,
        context="encryption_details",
    )
    for name in sorted(ENCRYPTION_FIELDS):
        _append_scalar(
            output,
            sample_id=task.task_id,
            field=f"encryption_details.{name}",
            value=_require_string(encryption[name], field=f"encryption_details.{name}"),
        )

    decoded_strings = value["decoded_strings"]
    if not isinstance(decoded_strings, dict) or not decoded_strings:
        raise AgentREGroundTruthError(
            "AgentRE field 'decoded_strings' must be a non-empty object"
        )
    for name in sorted(decoded_strings):
        normalized_name = _require_string(name, field="decoded_strings field name")
        if "." in normalized_name or "[" in normalized_name or "]" in normalized_name:
            raise AgentREGroundTruthError(
                f"AgentRE decoded_strings field name is ambiguous: {normalized_name!r}"
            )
        _append_scalar(
            output,
            sample_id=task.task_id,
            field=f"decoded_strings.{normalized_name}",
            value=_require_string(
                decoded_strings[name], field=f"decoded_strings.{normalized_name}"
            ),
        )

    anti_analysis = _require_string_list(value["anti_analysis"], field="anti_analysis")
    _append_string_list(
        output,
        sample_id=task.task_id,
        field="anti_analysis",
        values=anti_analysis,
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
        self.materializer.validate()
        output: list[RecoveryExpectation] = []
        for task in self._tasks:
            path, payload = _read_verified_ground_truth(self.materializer, task)
            output.extend(_parse_task(task, path, payload))
        return output
