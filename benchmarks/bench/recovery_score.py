"""Strict field-qualified scoring for deterministic value recovery."""

from __future__ import annotations

from collections import defaultdict

from .schema import (
    Outcome,
    RecoveryExpectation,
    RecoveryObservation,
    RecoveryScore,
)


def score_recovery(
    expectations: list[RecoveryExpectation],
    observations: list[RecoveryObservation],
) -> RecoveryScore:
    """Score exact recovered values without cross-field attribution.

    Identical observations are deduplicated. Distinct wrong values are false
    positives. A wrong value for an expected positive is both a false positive
    and a false negative because the required value was not recovered.
    """

    expected_by_key: dict[tuple[str, str], str | None] = {}
    for expectation in expectations:
        key = (expectation.sample_id, expectation.field)
        if key in expected_by_key:
            raise ValueError(
                "duplicate recovery expectation for "
                f"sample={expectation.sample_id!r}, field={expectation.field!r}"
            )
        expected_by_key[key] = expectation.value

    observed_by_key: dict[tuple[str, str], set[str]] = defaultdict(set)
    for observation in observations:
        observed_by_key[(observation.sample_id, observation.field)].add(
            observation.value
        )

    per_field: dict[str, Outcome] = defaultdict(Outcome)
    all_keys = expected_by_key.keys() | observed_by_key.keys()
    for key in all_keys:
        _sample_id, field = key
        outcome = per_field[field]
        expected = expected_by_key.get(key)
        observed = observed_by_key.get(key, set())

        if key not in expected_by_key or expected is None:
            outcome.fp += len(observed)
            continue

        if expected in observed:
            outcome.tp += 1
        else:
            outcome.fn += 1
        outcome.fp += len(observed - {expected})

    overall = Outcome(
        tp=sum(outcome.tp for outcome in per_field.values()),
        fp=sum(outcome.fp for outcome in per_field.values()),
        fn=sum(outcome.fn for outcome in per_field.values()),
    )
    return RecoveryScore(overall=overall, per_field=dict(per_field))


def normalize_agentre_c2(value: object | None) -> str | None:
    """Apply the pinned AgentRE scorer's decoded C2 normalization."""

    if value is None:
        return None
    return str(value).strip().lower().rstrip("/")


def score_agentre_decoded_c2(expected: object | None, observed: object | None) -> float:
    """Reproduce AgentRE decoded C2 credit: exact, same-host, or no credit."""

    expected_norm = normalize_agentre_c2(expected)
    observed_norm = normalize_agentre_c2(observed)
    if expected_norm == observed_norm:
        return 1.0
    if expected_norm is None or observed_norm is None:
        return 0.0

    expected_host = expected_norm.split("://")[-1].split("/")[0].split(":")[0]
    observed_host = observed_norm.split("://")[-1].split("/")[0].split(":")[0]
    return 0.5 if expected_host == observed_host else 0.0
