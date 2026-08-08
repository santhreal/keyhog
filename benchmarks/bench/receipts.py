"""Provenance-bound performance receipts.

One receipt binds a trial set to the exact binary bytes, Git commit, host
identity, and profile artifact digests that produced it, so a performance
claim is always traceable to immutable evidence and a swapped artifact or
stale binary breaks the digest.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass

from .schema import Host, ProfileArtifact, is_sha256
from .trials import TrialSet

RECEIPT_SCHEMA_VERSION = "perf-receipt-v1"
_GIT_HASH_RE = re.compile(r"[0-9a-f]{40}")


@dataclass(frozen=True)
class PerformanceReceipt:
    """Immutable provenance record for one role of one workload's trial set."""

    schema_version: str
    workload: str
    role: str
    binary_sha256: str
    git_hash: str
    hostname_hash: str
    os: str
    cpu: str
    trial_set_digest: str
    profile_artifacts: tuple[ProfileArtifact, ...]

    def __post_init__(self) -> None:
        if self.schema_version != RECEIPT_SCHEMA_VERSION:
            raise ValueError(
                f"receipt schema_version must be {RECEIPT_SCHEMA_VERSION!r}, "
                f"got {self.schema_version!r}"
            )
        if not self.workload:
            raise ValueError("receipt workload must be a non-empty string")
        if self.role not in ("control", "candidate", "unprofiled"):
            raise ValueError(f"receipt role is invalid: {self.role!r}")
        if not is_sha256(self.binary_sha256):
            raise ValueError("receipt binary_sha256 must be a lowercase SHA-256")
        if _GIT_HASH_RE.fullmatch(self.git_hash) is None:
            raise ValueError(
                "receipt git_hash must be a full lowercase Git commit"
            )
        if not self.hostname_hash:
            raise ValueError("receipt hostname_hash must be a non-empty string")
        if not is_sha256(self.trial_set_digest):
            raise ValueError("receipt trial_set_digest must be a lowercase SHA-256")

    def canonical_json(self) -> str:
        return json.dumps(self.to_json(), sort_keys=True, separators=(",", ":"))

    def digest(self) -> str:
        """Content digest over every provenance field, including artifacts."""
        return hashlib.sha256(self.canonical_json().encode("utf-8")).hexdigest()

    def to_json(self) -> dict:
        return {
            "schema_version": self.schema_version,
            "workload": self.workload,
            "role": self.role,
            "binary_sha256": self.binary_sha256,
            "git_hash": self.git_hash,
            "hostname_hash": self.hostname_hash,
            "os": self.os,
            "cpu": self.cpu,
            "trial_set_digest": self.trial_set_digest,
            "profile_artifacts": [
                artifact.to_json() for artifact in self.profile_artifacts
            ],
        }

    @classmethod
    def from_json(cls, value: object) -> "PerformanceReceipt":
        if not isinstance(value, dict):
            raise ValueError("performance receipt must be an object")
        required = set(cls.__dataclass_fields__)
        missing = sorted(required - set(value))
        extra = sorted(set(value) - required)
        if missing:
            raise ValueError(f"performance receipt missing required fields: {missing}")
        if extra:
            raise ValueError(f"performance receipt has unknown fields: {extra}")
        return cls(
            schema_version=str(value["schema_version"]),
            workload=str(value["workload"]),
            role=str(value["role"]),
            binary_sha256=str(value["binary_sha256"]),
            git_hash=str(value["git_hash"]),
            hostname_hash=str(value["hostname_hash"]),
            os=str(value["os"]),
            cpu=str(value["cpu"]),
            trial_set_digest=str(value["trial_set_digest"]),
            profile_artifacts=tuple(
                ProfileArtifact.from_json(a) for a in value["profile_artifacts"]
            ),
        )


def build_receipt(
    trial_set: TrialSet,
    *,
    binary_sha256: str,
    git_hash: str,
    host: Host,
) -> PerformanceReceipt:
    """Bind one trial set to its binary, commit, and host identity."""
    return PerformanceReceipt(
        schema_version=RECEIPT_SCHEMA_VERSION,
        workload=trial_set.workload,
        role=trial_set.role,
        binary_sha256=binary_sha256,
        git_hash=git_hash,
        hostname_hash=host.hostname_hash,
        os=host.os,
        cpu=host.cpu,
        trial_set_digest=trial_set.digest(),
        profile_artifacts=tuple(
            trial.profile for trial in trial_set.trials if trial.profile is not None
        ),
    )
