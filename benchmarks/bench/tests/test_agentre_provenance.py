import hashlib

import pytest

from bench.agentre_provenance import (
    CONTROL_ARTIFACTS,
    GROUND_TRUTH_ARTIFACTS,
    LINUX_TASKS,
    OFFICIAL_LINUX_SLICE,
    SOURCE_ARTIFACTS,
    UPSTREAM_REPOSITORY_COMMIT,
    PinnedArtifact,
)


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
