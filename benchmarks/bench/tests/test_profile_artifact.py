"""Locks the keyhog-profile v2 artifact reader and digest binding."""

import hashlib
import json

import pytest

from bench.profile_artifact import (
    CAUSAL_PROFILE_SCHEMA,
    CAUSAL_PROFILE_SCHEMA_MAJOR,
    MAX_PROFILE_ARTIFACT_BYTES,
    ProfileArtifactError,
    artifact_for,
    load_causal_profile,
    parse_causal_profile,
)


def _payload(stages=None, *, run_id="run-1", wall=1_000_000, minor=4,
             schema=CAUSAL_PROFILE_SCHEMA, major=CAUSAL_PROFILE_SCHEMA_MAJOR):
    if stages is None:
        stages = {"decode": (500_000, 2, 400_000), "entropy": (250_000, 1, 250_000)}
    return {
        "version": 5,
        "envelope": {
            "version": 1,
            "schema": schema,
            "schema_version": {"version": 1, "major": major, "minor": minor},
        },
        "identity": {"version": 1, "run_id": run_id},
        "status": "completed",
        "wall_time_ns": wall,
        "stages": [
            {"version": 1, "stage": name, "elapsed_ns": elapsed,
             "calls": calls, "attributed_ns": attributed}
            for name, (elapsed, calls, attributed) in stages.items()
        ],
    }


def _write(tmp_path, payload):
    path = tmp_path / "profile.json"
    path.write_text(json.dumps(payload))
    return path


def test_parse_valid_profile_exact_view():
    """The stage-gate compares these exact numbers; any drift in the parsed
    view corrupts every downstream ratio."""
    profile = parse_causal_profile(_payload(), source="test")
    assert profile.run_id == "run-1"
    assert profile.schema_minor == 4
    assert profile.wall_time_ns == 1_000_000
    stage_map = profile.stage_map()
    assert stage_map["decode"].elapsed_ns == 500_000
    assert stage_map["decode"].calls == 2
    assert stage_map["decode"].attributed_ns == 400_000
    assert stage_map["entropy"].elapsed_ns == 250_000


def test_parse_rejects_wrong_envelope_schema():
    """A v1 RunProfile JSON has a different shape; accepting it would compare
    the wrong numbers."""
    with pytest.raises(ProfileArtifactError, match="envelope schema"):
        parse_causal_profile(_payload(schema="keyhog-profile-v1"), source="t")


def test_parse_rejects_wrong_schema_major():
    """Only schema major 2 is understood; a future major must fail loudly."""
    with pytest.raises(ProfileArtifactError, match="schema major"):
        parse_causal_profile(_payload(major=3), source="t")


def test_parse_rejects_missing_envelope_and_identity():
    """The envelope and identity are the provenance spine of the artifact."""
    payload = _payload()
    del payload["envelope"]
    with pytest.raises(ProfileArtifactError, match="envelope"):
        parse_causal_profile(payload, source="t")
    payload = _payload()
    del payload["identity"]
    with pytest.raises(ProfileArtifactError, match="identity"):
        parse_causal_profile(payload, source="t")


def test_parse_rejects_duplicate_stage():
    """Stage comparisons assume one record per stage; a duplicate would make
    the ratio depend on map-insertion order."""
    payload = _payload()
    payload["stages"].append(dict(payload["stages"][0]))
    with pytest.raises(ProfileArtifactError, match="duplicate stage"):
        parse_causal_profile(payload, source="t")


def test_parse_rejects_negative_and_bool_numbers():
    """Negative or boolean timings are corrupt artifacts, not zero work."""
    payload = _payload(stages={"decode": (-1, 2, 0)})
    with pytest.raises(ProfileArtifactError, match="elapsed_ns"):
        parse_causal_profile(payload, source="t")
    payload = _payload(stages={"decode": (True, 2, 0)})
    with pytest.raises(ProfileArtifactError, match="elapsed_ns"):
        parse_causal_profile(payload, source="t")
    payload = _payload(wall=-5)
    with pytest.raises(ProfileArtifactError, match="wall_time_ns"):
        parse_causal_profile(payload, source="t")


def test_load_causal_profile_round_trip(tmp_path):
    """The on-disk loader enforces the same validation as the parser."""
    path = _write(tmp_path, _payload())
    profile = load_causal_profile(path)
    assert profile.run_id == "run-1"
    assert len(profile.stages) == 2


def test_load_rejects_invalid_json(tmp_path):
    """A truncated artifact (a partial write the CLI contract forbids) fails
    as invalid JSON, not as an empty profile."""
    path = tmp_path / "profile.json"
    path.write_text('{"envelope": ')
    with pytest.raises(ProfileArtifactError, match="invalid profile JSON"):
        load_causal_profile(path)


def test_load_enforces_size_cap(tmp_path, monkeypatch):
    """The shared 64 MiB cap matches the Rust reader; an oversized artifact
    is refused before parsing."""
    path = _write(tmp_path, _payload())
    monkeypatch.setattr(
        "bench.profile_artifact.MAX_PROFILE_ARTIFACT_BYTES", 16
    )
    with pytest.raises(ProfileArtifactError, match="bytes"):
        load_causal_profile(path)
    assert MAX_PROFILE_ARTIFACT_BYTES == 64 * 1024 * 1024


def test_artifact_for_binds_exact_bytes(tmp_path):
    """The reference digest must equal the SHA-256 of the artifact bytes so a
    swapped file breaks the binding."""
    path = _write(tmp_path, _payload())
    artifact = artifact_for(path)
    assert artifact.sha256 == hashlib.sha256(path.read_bytes()).hexdigest()
    assert artifact.bytes == len(path.read_bytes())
    assert artifact.path == str(path)
    assert artifact.profile_schema == "keyhog-profile"
    assert artifact.profile_schema_major == 2


def test_artifact_for_reference_override(tmp_path):
    """Gates store a result-relative reference while the digest still binds
    the absolute artifact bytes."""
    path = _write(tmp_path, _payload())
    artifact = artifact_for(path, reference="profiles/p.json")
    assert artifact.path == "profiles/p.json"


def test_artifact_for_rejects_unreadable_artifact(tmp_path):
    """A non-profile file must never receive a valid-looking reference."""
    path = tmp_path / "junk.json"
    path.write_text('{"not": "a profile"}')
    with pytest.raises(ProfileArtifactError, match="envelope"):
        artifact_for(path)
