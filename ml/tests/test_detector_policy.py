import pytest

import corpus
import detector_policy


def test_finding_identity_resolves_to_its_detector_owned_ml_mode():
    owner = detector_policy.resolve_detector("entropy-api-key:reassembled")
    assert owner["id"] == "generic-api-key"
    assert detector_policy.candidate_channel("entropy-api-key:reassembled") == "entropy"
    assert detector_policy.model_mode("entropy-api-key") == "authoritative"
    assert detector_policy.model_can_reduce_recall("entropy-api-key")

    assert detector_policy.candidate_channel("github-classic-pat") == "pattern"
    assert detector_policy.model_mode("github-classic-pat") == "lift"
    assert not detector_policy.model_can_reduce_recall("github-classic-pat")


def test_unknown_finding_identity_fails_instead_of_guessing_a_policy():
    with pytest.raises(ValueError, match="unknown detector or entropy owner"):
        detector_policy.resolve_detector("entropy-unknown")


def test_candidate_channel_cannot_disagree_with_finding_identity():
    with pytest.raises(ValueError, match="requires candidate_channel='entropy'"):
        detector_policy.validate_candidate_channel("entropy-api-key", "pattern")
    resolved = detector_policy.validate_candidate_channel("github-classic-pat", "pattern")
    assert resolved["id"] == "github-classic-pat"


def test_recall_sensitive_policy_coverage_names_every_suppressing_channel():
    assert detector_policy.recall_sensitive_finding_ids() == {
        "entropy-api-key",
        "entropy-generic",
        "entropy-password",
        "entropy-token",
    }


def test_generated_corpus_uses_the_emitted_finding_identity_for_each_channel():
    records = corpus.generate(n_per_unit=1, seed=7)

    positive_entropy_ids = {
        record["detector_id"]
        for record in records
        if record["candidate_channel"] == "entropy" and record["label"]
    }
    assert positive_entropy_ids == {
        "entropy-api-key",
        "entropy-generic",
        "entropy-password",
        "entropy-token",
    }
    for record in records:
        assert record["candidate_channel"] == detector_policy.candidate_channel(
            record["detector_id"]
        )
