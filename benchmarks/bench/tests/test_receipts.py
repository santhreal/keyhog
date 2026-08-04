"""Locks provenance receipt construction, digests, and validation."""

import pytest

from bench.receipts import PerformanceReceipt, build_receipt
from bench.schema import (
    PROFILE_ARTIFACT_SCHEMA_VERSION,
    Host,
    ProfileArtifact,
)
from bench.trials import NoiseReceipt, Trial, TrialSet

_DIGEST_A = "a" * 64
_DIGEST_B = "b" * 64
_GIT = "c" * 40


def _artifact(digest=_DIGEST_B) -> ProfileArtifact:
    return ProfileArtifact(
        schema_version=PROFILE_ARTIFACT_SCHEMA_VERSION,
        path="profiles/p.json",
        sha256=digest,
        bytes=128,
        profile_schema="keyhog-profile",
        profile_schema_major=2,
    )


def _noise() -> NoiseReceipt:
    return NoiseReceipt(
        affinity_requested=True, affinity_applied=True, affinity_cpus=8,
        governor="performance", governor_required="performance",
        frequency_mhz=4200.0,
        load_avg_before=(0.1, 0.1, 0.1), load_avg_after=(0.2, 0.1, 0.1),
    )


def _trial_set(with_profile=True) -> TrialSet:
    return TrialSet(
        schema_version="trial-set-v1",
        workload="mirror",
        role="control",
        trials=(
            Trial(index=0, cache_state="steady", wall_ms=10.0,
                  profile=_artifact() if with_profile else None,
                  noise=_noise(), invalid_reasons=()),
        ),
    )


def _receipt(**overrides) -> PerformanceReceipt:
    fields = {
        "schema_version": "perf-receipt-v1",
        "workload": "mirror",
        "role": "control",
        "binary_sha256": _DIGEST_A,
        "git_hash": _GIT,
        "hostname_hash": "82fcd9288623",
        "os": "linux",
        "cpu": "Test CPU",
        "trial_set_digest": _trial_set().digest(),
        "profile_artifacts": (_artifact(),),
    }
    fields.update(overrides)
    return PerformanceReceipt(**fields)


def test_build_receipt_binds_every_provenance_field():
    """The receipt is the auditable link from a performance claim to the
    binary, commit, host, trial set, and profile artifacts behind it."""
    trial_set = _trial_set()
    receipt = build_receipt(
        trial_set,
        binary_sha256=_DIGEST_A,
        git_hash=_GIT,
        host=Host(hostname_hash="82fcd9288623", os="linux", cpu="Test CPU"),
    )
    assert receipt.workload == "mirror"
    assert receipt.role == "control"
    assert receipt.binary_sha256 == _DIGEST_A
    assert receipt.git_hash == _GIT
    assert receipt.hostname_hash == "82fcd9288623"
    assert receipt.os == "linux"
    assert receipt.cpu == "Test CPU"
    assert receipt.trial_set_digest == trial_set.digest()
    assert receipt.profile_artifacts == (_artifact(),)


def test_build_receipt_skips_trials_without_profiles():
    """An unprofiled trial contributes no artifact reference, and none is
    invented."""
    receipt = build_receipt(
        _trial_set(with_profile=False),
        binary_sha256=_DIGEST_A,
        git_hash=_GIT,
        host=Host(hostname_hash="h", os="linux", cpu="c"),
    )
    assert receipt.profile_artifacts == ()


def test_receipt_digest_is_deterministic_and_sensitive():
    """The digest freezes the whole provenance record: identical inputs
    reproduce it, and any single-field change breaks it."""
    assert _receipt().digest() == _receipt().digest()
    assert _receipt(binary_sha256=_DIGEST_B).digest() != _receipt().digest()
    assert _receipt(git_hash="d" * 40).digest() != _receipt().digest()
    assert _receipt(trial_set_digest=_DIGEST_B).digest() != _receipt().digest()
    assert _receipt(
        profile_artifacts=(_artifact(digest=_DIGEST_A),)
    ).digest() != _receipt().digest()


def test_receipt_round_trip():
    """Receipts persist beside results; the codec must preserve every field,
    artifacts included."""
    receipt = _receipt()
    decoded = PerformanceReceipt.from_json(receipt.to_json())
    assert decoded == receipt
    assert decoded.digest() == receipt.digest()


def test_receipt_rejects_bad_provenance():
    """Malformed digests or roles mean the receipt was never bound to real
    evidence; reject at construction."""
    with pytest.raises(ValueError, match="binary_sha256"):
        _receipt(binary_sha256="short")
    with pytest.raises(ValueError, match="git_hash"):
        _receipt(git_hash="abc123")
    with pytest.raises(ValueError, match="trial_set_digest"):
        _receipt(trial_set_digest="xyz")
    with pytest.raises(ValueError, match="role"):
        _receipt(role="unknown")
    with pytest.raises(ValueError, match="schema_version"):
        _receipt(schema_version="perf-receipt-v0")
    with pytest.raises(ValueError, match="workload"):
        _receipt(workload="")


def test_receipt_from_json_strict():
    """A stored receipt with missing or unknown fields is corruption."""
    payload = _receipt().to_json()
    del payload["git_hash"]
    with pytest.raises(ValueError, match="missing required fields"):
        PerformanceReceipt.from_json(payload)
    payload = _receipt().to_json()
    payload["extra"] = True
    with pytest.raises(ValueError, match="unknown fields"):
        PerformanceReceipt.from_json(payload)
