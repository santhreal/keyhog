import hashlib
import json

import pytest

from bench.agentre_provenance import (
    CONTROL_ARTIFACTS,
    GROUND_TRUTH_ARTIFACTS,
    LINUX_TASKS,
    OFFICIAL_LINUX_SLICE,
    SOURCE_ARTIFACTS,
    UPSTREAM_REPOSITORY_COMMIT,
    PinnedArtifact,
    parse_linux_task_selection,
)


def task_manifest_document():
    tasks = [
        {
            "task_id": task.task_id,
            "source_file": task.source_path,
            "binary_name": task.binary_name,
            "ground_truth": task.ground_truth_path,
            "difficulty": task.difficulty,
        }
        for task in LINUX_TASKS
    ]
    tasks.extend(
        {
            "task_id": f"windows_level{difficulty}_fixture",
            "source_file": f"samples/windows_level{difficulty}_fixture.c",
            "binary_name": f"windows_level{difficulty}_fixture",
            "ground_truth": f"ground_truths/windows_level{difficulty}_fixture.json",
            "difficulty": difficulty,
        }
        for difficulty in range(14, 24)
    )
    return {"tasks": tasks}


def test_official_linux_slice_pins_all_13_source_truth_pairs():
    assert len(CONTROL_ARTIFACTS) == 4
    assert len(SOURCE_ARTIFACTS) == 13
    assert len(GROUND_TRUTH_ARTIFACTS) == 13
    assert len({artifact.path for artifact in OFFICIAL_LINUX_SLICE}) == 30
    assert {path.path.split("/", 1)[0] for path in SOURCE_ARTIFACTS} == {"samples"}
    assert {path.path.split("/", 1)[0] for path in GROUND_TRUTH_ARTIFACTS} == {
        "ground_truths"
    }
    assert [task.difficulty for task in LINUX_TASKS] == list(range(1, 14))
    assert {task.source_path for task in LINUX_TASKS} == {
        artifact.path for artifact in SOURCE_ARTIFACTS
    }
    assert {task.ground_truth_path for task in LINUX_TASKS} == {
        artifact.path for artifact in GROUND_TRUTH_ARTIFACTS
    }


def test_pinned_manifest_derives_exact_reviewed_linux_selection():
    raw = json.dumps(task_manifest_document())

    selection = parse_linux_task_selection(raw)

    assert selection.tasks == LINUX_TASKS
    assert selection.receipt() == {
        "schema": "agentre-linux-task-selection-v1",
        "selector": "exclude-task-id-prefix:windows_",
        "manifest_sha256": (
            "514523220d1915f4153a927cf66db9ef92901d4352964dc205271d872b338e8a"
        ),
        "selection_sha256": (
            "1bd43bf9751084b41165d12859dee509d50bd59e6a5aa2ba9fdc5a55adb891ac"
        ),
        "task_count": 13,
    }


@pytest.mark.parametrize("mutation", ["omission", "duplicate", "linux-drift"])
def test_manifest_selection_rejects_incomplete_ambiguous_or_changed_tasks(mutation):
    document = task_manifest_document()
    if mutation == "omission":
        document["tasks"].pop()
    elif mutation == "duplicate":
        document["tasks"][1]["task_id"] = document["tasks"][0]["task_id"]
    else:
        document["tasks"][0]["binary_name"] += "-changed"

    with pytest.raises(ValueError, match="rows|repeats|differs"):
        parse_linux_task_selection(json.dumps(document))


def test_manifest_selection_rejects_duplicate_json_keys():
    raw = json.dumps(task_manifest_document())
    raw = raw.replace('"task_id":', '"task_id": "shadow", "task_id":', 1)

    with pytest.raises(ValueError, match="repeats JSON key"):
        parse_linux_task_selection(raw)


def test_raw_urls_are_commit_pinned_and_encode_sample_spaces():
    artifact = next(item for item in SOURCE_ARTIFACTS if "ICMP" in item.path)
    assert UPSTREAM_REPOSITORY_COMMIT in artifact.raw_url
    assert artifact.raw_url.endswith("samples/level6_ICMP%20Covert%20Channel%20Shell.c")


def test_artifact_verification_accepts_only_pinned_bytes():
    payload = b"immutable upstream fixture"
    artifact = PinnedArtifact("samples/fixture.c", hashlib.sha256(payload).hexdigest())

    artifact.verify(payload)
    with pytest.raises(ValueError, match="digest mismatch"):
        artifact.verify(payload + b" changed")


@pytest.mark.parametrize("path", ["/absolute", "../escape", "a/../escape"])
def test_artifact_paths_cannot_escape_the_repository(path):
    with pytest.raises(ValueError, match="repository-relative"):
        PinnedArtifact(path, "a" * 64)
