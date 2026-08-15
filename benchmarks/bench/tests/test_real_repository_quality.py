"""Closes redacted real-repository gate coverage and freshness regressions."""

from __future__ import annotations

import copy
import json
from dataclasses import replace
from pathlib import Path

import pytest

from bench.real_repository_quality import (
    IDENTITY_SCHEMA,
    QualityGateError,
    RedactedFinding,
    RepositoryClass,
    RepositoryClassRegistry,
    deterministic_canary_sha256,
    evaluate_quality,
    load_evidence,
    load_evidence_directory,
    load_registry,
    validate_binary_identity,
)

_BENCH_ROOT = Path(__file__).resolve().parents[2]
_REGISTRY = _BENCH_ROOT / "quality" / "repository-classes.toml"
_EVIDENCE = _BENCH_ROOT / "quality" / "synthetic-evidence"
_IDENTITY = {
    "schema": IDENTITY_SCHEMA,
    "executable_sha256": "a" * 64,
    "source_commit": "b" * 40,
    "source_version": "0.5.70",
    "detector_set_digest": "926-4168e2c6c93a16ca",
}


def _loaded():
    return load_registry(_REGISTRY), load_evidence_directory(_EVIDENCE)


def _fixture(name: str = "rc-001.json") -> dict[str, object]:
    return json.loads((_EVIDENCE / name).read_text(encoding="utf-8"))


def _write_fixture(tmp_path: Path, value: dict[str, object]) -> Path:
    path = tmp_path / "evidence.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


def test_synthetic_registry_passes_at_exact_quality_boundaries_without_sensitive_bytes():
    registry, evidence = _loaded()
    receipt = validate_binary_identity(_IDENTITY, _IDENTITY)

    report = evaluate_quality(registry, evidence, receipt, receipt)

    classes = {row["repository_class_id"]: row for row in report["repository_classes"]}
    assert classes["rc-001"] == {
        "repository_class_id": "rc-001",
        "redacted_label": "[redacted:rc-001]",
        "source_content_sha256": "1" * 64,
        "source_lines": 1_000_000,
        "findings_per_mloc": 2.0,
        "blocking_false_positives": 0,
        "recall": 1.0,
        "canary_recall": 1.0,
        "labels": [
            {
                "redacted_label": "[redacted:label-0001]",
                "content_sha256": "2" + "1" * 63,
                "outcome": "matched",
            }
        ],
        "canaries": [
            {
                "redacted_label": "[redacted:canary-0001]",
                "content_sha256": (
                    "ce4204ab2dc868d23c8d4c8fc9ca9b602cf3c0f1f611a453d3ea7e5855255351"
                ),
                "outcome": "matched",
            }
        ],
        "findings": [
            {
                "content_sha256": "2" + "1" * 63,
                "redacted_label": "[redacted:label-0001]",
                "evidence": {
                    "tier": "likely",
                    "reason_code": "vendor-pattern",
                },
            },
            {
                "content_sha256": (
                    "ce4204ab2dc868d23c8d4c8fc9ca9b602cf3c0f1f611a453d3ea7e5855255351"
                ),
                "redacted_label": "[redacted:canary-0001]",
                "evidence": {
                    "tier": "confirmed",
                    "reason_code": "checksum-valid",
                },
            },
            {
                "content_sha256": "3" + "1" * 63,
                "redacted_label": None,
                "evidence": {
                    "tier": "review",
                    "reason_code": "documentation",
                },
            },
            {
                "content_sha256": "4" + "1" * 63,
                "redacted_label": None,
                "evidence": {
                    "tier": "review",
                    "reason_code": "test-fixture",
                },
            },
        ],
    }
    encoded = json.dumps(report, sort_keys=True)
    assert "/" not in encoded
    assert "\\" not in encoded
    assert "repository_path" not in encoded
    assert "plaintext" not in encoded


@pytest.mark.parametrize("unsafe_key", ["repository_path", "repository_name", "plaintext_label", "raw_finding"])
def test_evidence_rejects_every_plaintext_or_repository_locator_field(tmp_path: Path, unsafe_key: str):
    value = _fixture()
    value[unsafe_key] = "sensitive-value"

    with pytest.raises(QualityGateError, match="schema is invalid"):
        load_evidence(_write_fixture(tmp_path, value))


def test_evidence_rejects_noncanonical_redacted_label_without_echoing_it(tmp_path: Path):
    value = _fixture()
    value["redacted_label"] = "private-repository-name"

    with pytest.raises(QualityGateError, match="redacted label is not canonical") as raised:
        load_evidence(_write_fixture(tmp_path, value))
    assert "private-repository-name" not in str(raised.value)


@pytest.mark.parametrize(
    ("old", "new", "message"),
    [
        ("min_recall = 1.0", "min_recall = 0.99", "recall floors must be exact"),
        (
            "min_canary_recall = 1.0",
            "min_canary_recall = 0.99",
            "recall floors must be exact",
        ),
        (
            "max_blocking_false_positives = 0",
            "max_blocking_false_positives = 1",
            "must be zero",
        ),
    ],
)
def test_registry_cannot_weaken_exact_recall_or_blocking_fp_contract(
    tmp_path: Path, old: str, new: str, message: str
):
    raw = _REGISTRY.read_text(encoding="utf-8").replace(old, new, 1)
    path = tmp_path / "registry.toml"
    path.write_text(raw, encoding="utf-8")

    with pytest.raises(QualityGateError, match=message):
        load_registry(path)


def test_runtime_registry_addition_fails_until_new_class_has_evidence():
    registry, evidence = _loaded()
    classes = dict(registry.classes)
    classes["rc-003"] = RepositoryClass(
        class_id="rc-003",
        redacted_label="[redacted:rc-003]",
        max_findings_per_mloc=classes["rc-001"].max_findings_per_mloc,
        max_blocking_false_positives=0,
        min_recall=classes["rc-001"].min_recall,
        min_canary_recall=classes["rc-001"].min_canary_recall,
    )

    with pytest.raises(QualityGateError, match="coverage is incomplete"):
        evaluate_quality(RepositoryClassRegistry(classes), evidence, _IDENTITY, _IDENTITY)


@pytest.mark.parametrize("drop_class", ["rc-001", "rc-002"])
def test_every_manifest_class_is_required(drop_class: str):
    registry, evidence = _loaded()
    incomplete = dict(evidence)
    del incomplete[drop_class]

    with pytest.raises(QualityGateError, match="coverage is incomplete"):
        evaluate_quality(registry, incomplete, _IDENTITY, _IDENTITY)


def test_findings_per_mloc_passes_at_limit_and_fails_one_finding_over():
    registry, evidence = _loaded()
    evaluate_quality(registry, evidence, _IDENTITY, _IDENTITY)
    samples = dict(evidence)
    first = samples["rc-001"]
    extra = RedactedFinding(
        content_sha256="f" * 64,
        label=None,
        evidence_tier="review",
        evidence_reason_code="documentation",
    )
    samples["rc-001"] = replace(first, findings=first.findings + (extra,))

    with pytest.raises(QualityGateError, match="rc-001:findings-per-mloc"):
        evaluate_quality(registry, samples, _IDENTITY, _IDENTITY)


def test_default_policy_blocking_false_positive_fails_even_within_density_limit():
    registry, evidence = _loaded()
    samples = dict(evidence)
    first = samples["rc-001"]
    blocking = replace(
        first.findings[-1],
        evidence_tier="likely",
        evidence_reason_code="vendor-pattern",
    )
    samples["rc-001"] = replace(first, findings=first.findings[:-1] + (blocking,))

    with pytest.raises(QualityGateError, match="rc-001:blocking-false-positives"):
        evaluate_quality(registry, samples, _IDENTITY, _IDENTITY)


def test_per_class_recall_rejects_a_recorded_miss():
    registry, evidence = _loaded()
    samples = dict(evidence)
    first = samples["rc-001"]
    missed = replace(first.labels[0], outcome="missed")
    samples["rc-001"] = replace(
        first,
        labels=(missed,),
        findings=tuple(finding for finding in first.findings if finding.label != missed.redacted_label),
    )

    with pytest.raises(QualityGateError, match="rc-001:recall"):
        evaluate_quality(registry, samples, _IDENTITY, _IDENTITY)


def test_canary_recall_rejects_a_recorded_miss():
    registry, evidence = _loaded()
    samples = dict(evidence)
    first = samples["rc-001"]
    missed = replace(first.canaries[0], outcome="missed")
    samples["rc-001"] = replace(
        first,
        canaries=(missed,),
        findings=tuple(finding for finding in first.findings if finding.label != missed.redacted_label),
    )

    with pytest.raises(QualityGateError, match="rc-001:canary-recall"):
        evaluate_quality(registry, samples, _IDENTITY, _IDENTITY)


def test_absent_canary_outcome_is_malformed_not_an_implicit_miss(tmp_path: Path):
    value = _fixture()
    del value["canaries"][0]["outcome"]

    with pytest.raises(QualityGateError, match="ground-truth label schema is invalid"):
        load_evidence(_write_fixture(tmp_path, value))


def test_canary_digest_is_deterministic_and_tampering_fails(tmp_path: Path):
    assert deterministic_canary_sha256("rc-001", "[redacted:canary-0001]") == (
        "ce4204ab2dc868d23c8d4c8fc9ca9b602cf3c0f1f611a453d3ea7e5855255351"
    )
    value = _fixture()
    value["canaries"][0]["content_sha256"] = "e" * 64

    with pytest.raises(QualityGateError, match="canary content hash is invalid"):
        load_evidence(_write_fixture(tmp_path, value))


def test_labeled_finding_hash_must_match_ground_truth_hash(tmp_path: Path):
    value = _fixture()
    value["findings"][0]["content_sha256"] = "e" * 64

    with pytest.raises(QualityGateError, match="content hash disagrees"):
        load_evidence(_write_fixture(tmp_path, value))


def test_outcome_must_agree_with_observed_finding(tmp_path: Path):
    value = _fixture()
    value["canaries"][0]["outcome"] = "missed"

    with pytest.raises(QualityGateError, match="outcome disagrees"):
        load_evidence(_write_fixture(tmp_path, value))


def test_evidence_tier_must_match_canonical_reason(tmp_path: Path):
    value = _fixture()
    value["findings"][0]["evidence"]["tier"] = "review"

    with pytest.raises(QualityGateError, match="tier does not match"):
        load_evidence(_write_fixture(tmp_path, value))


def test_stale_and_mismatched_binary_receipt_fields_fail_closed():
    for field, replacement in (
        ("executable_sha256", "c" * 64),
        ("source_commit", "d" * 40),
        ("source_version", "0.5.69"),
        ("detector_set_digest", "925-4168e2c6c93a16ca"),
    ):
        stale = copy.deepcopy(_IDENTITY)
        stale[field] = replacement
        with pytest.raises(QualityGateError, match="stale or mismatched"):
            validate_binary_identity(stale, _IDENTITY)


def test_quality_report_identity_is_checked_against_current_binary():
    registry, evidence = _loaded()
    stale = {**_IDENTITY, "executable_sha256": "c" * 64}

    with pytest.raises(QualityGateError, match="stale or mismatched"):
        evaluate_quality(registry, evidence, stale, _IDENTITY)


def test_malformed_identity_receipt_rejects_extra_paths_and_bad_hashes():
    with_path = {**_IDENTITY, "binary_path": "/private/build/keyhog"}
    with pytest.raises(QualityGateError, match="schema is invalid"):
        validate_binary_identity(with_path, _IDENTITY)
    bad_hash = {**_IDENTITY, "executable_sha256": "A" * 64}
    with pytest.raises(QualityGateError, match="lowercase SHA-256"):
        validate_binary_identity(bad_hash, bad_hash)
