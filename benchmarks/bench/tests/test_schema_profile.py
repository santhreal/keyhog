"""Locks the RunResult causal-profile binding: optional, validated on load."""

import pytest

from bench.schema import (
    PROFILE_ARTIFACT_SCHEMA_VERSION,
    ProfileArtifact,
    RunResult,
)

_DIGEST = "b" * 64


def _artifact(**overrides) -> ProfileArtifact:
    fields = {
        "schema_version": PROFILE_ARTIFACT_SCHEMA_VERSION,
        "path": "profiles/control-mirror-profile.json",
        "sha256": _DIGEST,
        "bytes": 4096,
        "profile_schema": "keyhog-profile",
        "profile_schema_major": 2,
    }
    fields.update(overrides)
    return ProfileArtifact(**fields)


def test_profile_artifact_round_trip():
    """The reference is the receipt a gate resolves; field loss or reordering
    in the codec would break digest comparisons downstream."""
    artifact = _artifact()
    assert ProfileArtifact.from_json(artifact.to_json()) == artifact


def test_profile_artifact_rejects_bad_digest():
    """A non-SHA-256 digest means the artifact was never content-bound;
    reject it at construction, not at gate time."""
    with pytest.raises(ValueError, match="sha256"):
        _artifact(sha256="not-a-digest")
    with pytest.raises(ValueError, match="sha256"):
        _artifact(sha256=_DIGEST.upper())


def test_profile_artifact_rejects_bad_fields():
    """Each field is validated so a hand-edited artifact reference fails on
    load instead of propagating into receipts."""
    with pytest.raises(ValueError, match="schema_version"):
        _artifact(schema_version="profile-artifact-v0")
    with pytest.raises(ValueError, match="path"):
        _artifact(path="")
    with pytest.raises(ValueError, match="bytes"):
        _artifact(bytes=0)
    with pytest.raises(ValueError, match="bytes"):
        _artifact(bytes=True)
    with pytest.raises(ValueError, match="profile_schema"):
        _artifact(profile_schema="")
    with pytest.raises(ValueError, match="profile_schema_major"):
        _artifact(profile_schema_major=-1)


def test_profile_artifact_from_json_strict():
    """Missing or unknown keys in a stored reference are corruption, not
    optional data."""
    with pytest.raises(ValueError, match="must be an object"):
        ProfileArtifact.from_json("nope")
    payload = _artifact().to_json()
    del payload["bytes"]
    with pytest.raises(ValueError, match="missing required fields"):
        ProfileArtifact.from_json(payload)
    payload = _artifact().to_json()
    payload["surprise"] = 1
    with pytest.raises(ValueError, match="unknown fields"):
        ProfileArtifact.from_json(payload)


def test_run_result_without_profile_round_trips_unchanged():
    """Rows recorded before profile capture must serialize without the key so
    existing result files stay byte-identical."""
    result = RunResult()
    assert "profile" not in result.to_json()
    decoded = RunResult.from_json(result.to_json())
    assert decoded.profile is None


def test_run_result_with_profile_round_trips():
    """A profiled row carries its artifact reference through the JSON codec
    losslessly."""
    result = RunResult(profile=_artifact())
    decoded = RunResult.from_json(result.to_json())
    assert decoded.profile == _artifact()
    assert decoded.to_json() == result.to_json()


def test_run_result_rejects_invalid_profile_on_load():
    """Validation happens at load: a tampered artifact reference in a result
    file fails before any gate consumes it."""
    payload = RunResult(profile=_artifact()).to_json()
    payload["profile"]["sha256"] = "tampered"
    with pytest.raises(ValueError, match="sha256"):
        RunResult.from_json(payload)


def test_legacy_schema_rejects_profile_field():
    """A legacy bench-v3 row carrying current profile telemetry is
    contradictory and must be rejected, matching the other v4 fields."""
    payload = RunResult().to_json()
    payload["schema_version"] = "bench-v3"
    payload["profile"] = _artifact().to_json()
    with pytest.raises(ValueError, match="legacy schema"):
        RunResult.from_json(payload)
