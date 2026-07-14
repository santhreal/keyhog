import pytest

from bench.recovery_score import score_agentre_decoded_c2, score_recovery
from bench.schema import RecoveryExpectation, RecoveryObservation, RecoveryScore


def expectation(field: str, value: str | None) -> RecoveryExpectation:
    return RecoveryExpectation("level13", field, value)


def observation(field: str, value: str) -> RecoveryObservation:
    return RecoveryObservation("level13", field, value)


def test_field_qualification_prevents_cross_field_credit():
    value = "http://10.0.0.8:8080/poll"
    result = score_recovery(
        [
            expectation("decoded_c2", value),
            expectation("decoded_strings.c2_url", value),
        ],
        [observation("decoded_c2", value)],
    )

    assert result.overall.to_json() == {
        "tp": 1,
        "fp": 0,
        "fn": 1,
        "precision": 1.0,
        "recall": 0.5,
        "f1": 0.6667,
    }
    assert RecoveryScore.from_json(result.to_json()).to_json() == result.to_json()


def test_absence_and_wrong_values_have_honest_confusion_counts():
    result = score_recovery(
        [expectation("decoded_c2", None), expectation("encryption_key", "correct")],
        [observation("decoded_c2", "invented"), observation("encryption_key", "wrong")],
    )

    assert (result.overall.tp, result.overall.fp, result.overall.fn) == (0, 2, 1)
    assert (
        result.per_field["decoded_c2"].tp,
        result.per_field["decoded_c2"].fp,
        result.per_field["decoded_c2"].fn,
    ) == (0, 1, 0)
    assert (
        result.per_field["encryption_key"].tp,
        result.per_field["encryption_key"].fp,
        result.per_field["encryption_key"].fn,
    ) == (0, 1, 1)


def test_unexpected_sample_and_field_are_false_positives():
    result = score_recovery(
        [expectation("decoded_c2", None)],
        [RecoveryObservation("unknown-level", "invented_field", "invented")],
    )

    assert (result.overall.tp, result.overall.fp, result.overall.fn) == (0, 1, 0)
    assert result.per_field["invented_field"].fp == 1


def test_scoring_is_exact_and_deduplicates_identical_observations():
    expected = expectation("decoded_c2", "https://example.test/path")
    duplicate = observation("decoded_c2", "https://example.test/path")
    result = score_recovery(
        [expected],
        [duplicate, duplicate, observation("decoded_c2", "https://example.test/path/")],
    )

    assert (result.overall.tp, result.overall.fp, result.overall.fn) == (1, 1, 0)


def test_duplicate_expectations_are_rejected():
    with pytest.raises(ValueError, match="duplicate recovery expectation"):
        score_recovery(
            [expectation("decoded_c2", "one"), expectation("decoded_c2", "two")],
            [],
        )


def test_recovery_score_rejects_an_unknown_schema_version():
    payload = score_recovery([], []).to_json()
    payload["schema_version"] = "recovery-v999"

    with pytest.raises(ValueError, match="unsupported recovery score schema"):
        RecoveryScore.from_json(payload)


@pytest.mark.parametrize(
    ("expected", "observed", "credit"),
    [
        (None, None, 1.0),
        ("HTTP://Example.Test/path/", "http://example.test/path", 1.0),
        ("https://example.test:443/a", "http://example.test:80/b", 0.5),
        ("https://one.test/a", "https://two.test/a", 0.0),
        ("https://one.test/a", None, 0.0),
    ],
)
def test_agentre_decoded_c2_credit_matches_upstream(expected, observed, credit):
    assert score_agentre_decoded_c2(expected, observed) == credit
