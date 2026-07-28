"""Behavioral tests for the Unicode CPU/SIMD parity publication boundary."""

from __future__ import annotations

import pytest

from bench.hosted_cpu_gate import CONTEXT_SCHEMA, HostedCpuInputError, PARITY_SCHEMA
from bench.unicode_parity import build_receipt, parse_summary

_EXAMPLES = 848
_SHA = {
    "context": "c" * 64,
    "release": "d" * 64,
    "test": "e" * 64,
    "source": "f" * 64,
    "vector": "1" * 64,
}


def _context():
    return {
        "schema_version": CONTEXT_SCHEMA,
        "source_commit": "a" * 40,
        "detector_corpus_sha256": "b" * 64,
        "policy_sha256": "2" * 64,
        "runner": {
            "repository": "santhreal/keyhog",
            "workflow_ref": "santhreal/keyhog/.github/workflows/bench-nightly.yml@refs/heads/main",
            "workflow_sha": "a" * 40,
            "run_id": "1234",
            "run_attempt": "1",
            "job": "leaderboard",
        },
    }


def _summary(count: int = _EXAMPLES) -> str:
    return (
        f"backend parity: {count} detector examples; "
        "CPU == SIMD on all ASCII inputs; 0 unicode-input divergences"
    )


def _receipt(output: str):
    return build_receipt(
        _context(),
        output,
        expected_examples=_EXAMPLES,
        context_sha256=_SHA["context"],
        release_executable_sha256=_SHA["release"],
        test_executable_sha256=_SHA["test"],
        parity_source_sha256=_SHA["source"],
        vector_sha256=_SHA["vector"],
        command=["/tmp/parity-test", "--nocapture"],
        generated_at="2026-07-27T10:00:00+00:00",
    )


def test_explicit_zero_unicode_divergence_produces_fully_bound_receipt():
    """A floating explicit-zero once omitted run/binary/vector identity; every axis is now persisted."""
    receipt = _receipt(_summary())
    assert receipt["schema_version"] == PARITY_SCHEMA
    assert receipt["detector_examples"] == _EXAMPLES
    assert receipt["unicode_divergences"] == 0
    assert receipt["source_commit"] == "a" * 40
    assert receipt["context_sha256"] == _SHA["context"]
    assert receipt["test_executable_sha256"] == _SHA["test"]
    assert receipt["vector_sha256"] == _SHA["vector"]
    assert receipt["run_id"] == "1234"


def test_any_unicode_divergence_prevents_receipt_publication():
    """Tracked positive divergence output once looked informational; only literal zero can publish."""
    output = (
        f"backend parity: {_EXAMPLES} detector examples; CPU == SIMD on all ASCII inputs; "
        "10 unicode-input divergences (tracked finding)"
    )
    with pytest.raises(HostedCpuInputError, match="no unique explicit-zero"):
        parse_summary(output, expected_examples=_EXAMPLES)


def test_policy_pinned_example_count_rejects_shrunk_vector_set():
    """A hard-coded minimum once let deleted vectors false-pass; exact reviewed count detects shrinkage."""
    with pytest.raises(HostedCpuInputError, match="expected 848"):
        parse_summary(_summary(847), expected_examples=_EXAMPLES)


def test_missing_legacy_or_ambiguous_summary_fails_closed():
    """Missing, legacy-suffixed, or duplicate summaries once crashed/ambiguously passed; all are rejected."""
    legacy = _summary() + " (tracked finding)"
    with pytest.raises(HostedCpuInputError, match="no unique explicit-zero"):
        parse_summary("test passed without a receipt", expected_examples=_EXAMPLES)
    with pytest.raises(HostedCpuInputError, match="no unique explicit-zero"):
        parse_summary(legacy, expected_examples=_EXAMPLES)
    with pytest.raises(HostedCpuInputError, match="no unique explicit-zero"):
        parse_summary(_summary() + "\n" + _summary(), expected_examples=_EXAMPLES)


@pytest.mark.parametrize(
    "malformed",
    [
        " backend parity: 848 detector examples; CPU == SIMD on all ASCII inputs; 0 unicode-input divergences",
        "backend parity: 848 detector examples;  CPU == SIMD on all ASCII inputs; 0 unicode-input divergences",
        "backend parity: many detector examples; CPU == SIMD on all ASCII inputs; 0 unicode-input divergences",
        "backend parity: 848 detector examples; CPU == SIMD on all ASCII inputs; 0 unicode-input divergences (ok)",
        "backend parity: 848 detector examples; CPU == SIMD on every input",
    ],
)
def test_malformed_success_summary_is_not_accepted(malformed):
    """Permissive summary parsing once admitted near-miss strings; exact syntax prevents forged success."""
    with pytest.raises(HostedCpuInputError, match="no unique explicit-zero"):
        parse_summary(malformed, expected_examples=_EXAMPLES)
