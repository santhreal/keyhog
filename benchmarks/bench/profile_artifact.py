"""Causal profile artifact capture and the ``keyhog-profile`` v2 JSON reader.

The keyhog binary writes one drained causal profile when invoked with
``--profile-out <PATH>`` (atomically; a nonzero exit leaves no partial
artifact). This module parses that envelope into the exact stage-latency
view the benchmark gates compare, and binds artifact bytes to a
:class:`bench.schema.ProfileArtifact` reference + digest.
"""

from __future__ import annotations

import json
import pathlib
from dataclasses import dataclass

from .executable_snapshot import sha256_file
from .schema import PROFILE_ARTIFACT_SCHEMA_VERSION, ProfileArtifact

PROFILE_OUT_FLAG = "--profile-out"
CAUSAL_PROFILE_SCHEMA = "keyhog-profile"
CAUSAL_PROFILE_SCHEMA_MAJOR = 2
# Matches the Rust reader cap in crates/profile/src/bin/keyhog-profile.rs.
MAX_PROFILE_ARTIFACT_BYTES = 64 * 1024 * 1024


class ProfileArtifactError(ValueError):
    """A profile artifact that is missing, oversized, or fails validation."""


def _non_negative_int(value: object, field_name: str, source: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ProfileArtifactError(
            f"{source}: {field_name} must be a non-negative integer, "
            f"got {value!r}"
        )
    return value


@dataclass(frozen=True)
class StageLatency:
    """One stage's aggregate latency exactly as recorded by the profiler."""

    stage: str
    elapsed_ns: int
    calls: int
    attributed_ns: int


@dataclass(frozen=True)
class CausalProfile:
    """The validated, comparison-relevant view of one causal profile artifact."""

    run_id: str
    schema_minor: int
    wall_time_ns: int
    stages: tuple[StageLatency, ...]

    def stage_map(self) -> dict[str, StageLatency]:
        return {stage.stage: stage for stage in self.stages}


def parse_causal_profile(payload: object, *, source: str) -> CausalProfile:
    """Validate one decoded ``keyhog-profile`` v2 envelope."""
    if not isinstance(payload, dict):
        raise ProfileArtifactError(f"{source}: profile must be a JSON object")
    envelope = payload.get("envelope")
    if not isinstance(envelope, dict):
        raise ProfileArtifactError(f"{source}: profile lacks an envelope object")
    schema = envelope.get("schema")
    if schema != CAUSAL_PROFILE_SCHEMA:
        raise ProfileArtifactError(
            f"{source}: envelope schema is {schema!r}, expected "
            f"{CAUSAL_PROFILE_SCHEMA!r}; re-record the profile with the "
            "current profiler"
        )
    schema_version = envelope.get("schema_version")
    if not isinstance(schema_version, dict):
        raise ProfileArtifactError(
            f"{source}: envelope lacks a schema_version object"
        )
    major = schema_version.get("major")
    if major != CAUSAL_PROFILE_SCHEMA_MAJOR:
        raise ProfileArtifactError(
            f"{source}: envelope schema major is {major!r}, supported major is "
            f"{CAUSAL_PROFILE_SCHEMA_MAJOR}"
        )
    minor = _non_negative_int(
        schema_version.get("minor"), "envelope.schema_version.minor", source
    )
    identity = payload.get("identity")
    if not isinstance(identity, dict):
        raise ProfileArtifactError(f"{source}: profile lacks an identity object")
    run_id = identity.get("run_id")
    if not isinstance(run_id, str):
        raise ProfileArtifactError(
            f"{source}: identity.run_id must be a string, got {run_id!r}"
        )
    wall_time_ns = _non_negative_int(
        payload.get("wall_time_ns"), "wall_time_ns", source
    )
    raw_stages = payload.get("stages")
    if not isinstance(raw_stages, list):
        raise ProfileArtifactError(f"{source}: profile stages must be an array")
    stages: list[StageLatency] = []
    seen: set[str] = set()
    for index, raw_stage in enumerate(raw_stages):
        stage_source = f"{source} stage[{index}]"
        if not isinstance(raw_stage, dict):
            raise ProfileArtifactError(f"{stage_source}: must be an object")
        name = raw_stage.get("stage")
        if not isinstance(name, str) or not name:
            raise ProfileArtifactError(
                f"{stage_source}: stage must be a non-empty string"
            )
        if name in seen:
            raise ProfileArtifactError(
                f"{stage_source}: duplicate stage {name!r}; a profile records "
                "each stage exactly once"
            )
        seen.add(name)
        stages.append(
            StageLatency(
                stage=name,
                elapsed_ns=_non_negative_int(
                    raw_stage.get("elapsed_ns"), "elapsed_ns", stage_source
                ),
                calls=_non_negative_int(
                    raw_stage.get("calls"), "calls", stage_source
                ),
                attributed_ns=_non_negative_int(
                    raw_stage.get("attributed_ns"), "attributed_ns", stage_source
                ),
            )
        )
    return CausalProfile(
        run_id=run_id,
        schema_minor=minor,
        wall_time_ns=wall_time_ns,
        stages=tuple(stages),
    )


def read_profile_bytes(path: pathlib.Path) -> bytes:
    """Read one artifact enforcing the shared 64 MiB cap, never a partial read."""
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise ProfileArtifactError(
            f"cannot stat profile artifact {path}: {exc}"
        ) from exc
    if size > MAX_PROFILE_ARTIFACT_BYTES:
        raise ProfileArtifactError(
            f"profile artifact {path} is {size} bytes; the limit is "
            f"{MAX_PROFILE_ARTIFACT_BYTES} bytes"
        )
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise ProfileArtifactError(
            f"cannot read profile artifact {path}: {exc}"
        ) from exc
    if len(data) > MAX_PROFILE_ARTIFACT_BYTES:
        raise ProfileArtifactError(
            f"profile artifact {path} grew beyond the "
            f"{MAX_PROFILE_ARTIFACT_BYTES}-byte limit while reading"
        )
    return data


def load_causal_profile(path: str | pathlib.Path) -> CausalProfile:
    """Load and validate one ``keyhog-profile`` v2 artifact from disk."""
    profile_path = pathlib.Path(path)
    data = read_profile_bytes(profile_path)
    try:
        payload = json.loads(data)
    except json.JSONDecodeError as exc:
        raise ProfileArtifactError(
            f"invalid profile JSON in {profile_path}: {exc}"
        ) from exc
    return parse_causal_profile(payload, source=str(profile_path))


def artifact_for(
    profile_path: str | pathlib.Path,
    *,
    reference: str | None = None,
) -> ProfileArtifact:
    """Digest one on-disk artifact into a result-embedded reference.

    The artifact is parsed before digesting so a result can never reference
    bytes the gates could not read.
    """
    path = pathlib.Path(profile_path)
    profile = load_causal_profile(path)
    del profile  # validation only; the digest binds the bytes
    data = read_profile_bytes(path)
    return ProfileArtifact(
        schema_version=PROFILE_ARTIFACT_SCHEMA_VERSION,
        path=reference if reference is not None else str(path),
        sha256=sha256_file(path),
        bytes=len(data),
        profile_schema=CAUSAL_PROFILE_SCHEMA,
        profile_schema_major=CAUSAL_PROFILE_SCHEMA_MAJOR,
    )
