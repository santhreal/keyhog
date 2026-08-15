import hashlib
import json
import types

import numpy as np
import pytest

import train_classifier


def test_serialized_weights_round_trip_preserves_model_scores(tmp_path):
    import torch

    model = train_classifier.build_model(55)
    inputs = torch.linspace(-1.0, 1.0, steps=110, dtype=torch.float32).reshape(2, 55)
    with torch.no_grad():
        expected = model(inputs).clone()
    path = tmp_path / "weights.bin"
    path.write_bytes(train_classifier.serialize(model, 55))

    restored = train_classifier.build_model(55)
    train_classifier.load_serialized_weights(restored, str(path), 55)
    with torch.no_grad():
        actual = restored(inputs)
    assert torch.equal(actual, expected)


def test_serialized_weights_rejects_wrong_feature_layout(tmp_path):
    path = tmp_path / "weights.bin"
    path.write_bytes(b"\0" * 16)
    with pytest.raises(ValueError, match="architecture requires"):
        train_classifier.load_serialized_weights(
            train_classifier.build_model(55), str(path), 55
        )

def test_quantized_serializer_reproduces_shipped_artifact_exactly():
    weights = (
        train_classifier.REPO_ROOT / "crates/scanner/src/weights.bin"
    ).read_bytes()
    expected = (
        train_classifier.REPO_ROOT / "crates/scanner/src/quantized_moe.bin"
    ).read_bytes()
    assert train_classifier.serialize_quantized(weights, 55) == expected


def test_quantized_serializer_rejects_stale_width_and_nonfinite_weights():
    with pytest.raises(ValueError, match="55-feature schema"):
        train_classifier.serialize_quantized(b"", 51)
    with pytest.raises(ValueError, match="expected"):
        train_classifier.serialize_quantized(b"", 55)
    parameters = np.zeros(train_classifier.parameter_count(55), dtype="<f4")
    parameters[0] = np.nan
    with pytest.raises(ValueError, match="non-finite"):
        train_classifier.serialize_quantized(parameters.tobytes(), 55)
    parameters.fill(1_000_000.0)
    with pytest.raises(ValueError, match="VYRE i32 arithmetic bound"):
        train_classifier.serialize_quantized(parameters.tobytes(), 55)


def test_probe_gate_rejects_reversed_positive_and_negative_contracts():
    assert train_classifier.probe_gate_error(
        {
            "positive": {"score": 0.49, "want": "high"},
            "negative": {"score": 0.50, "want": "low"},
        }
    ) == (
        "REFUSING model: canonical probe contract failed: "
        "positive: score 0.490 < 0.500; negative: score 0.500 >= 0.500\n"
    )
    assert not train_classifier.probe_gate_error(
        {
            "positive": {"score": 0.50, "want": "high"},
            "negative": {"score": 0.49, "want": "low"},
        }
    )


def _bench_config(scanner):
    configs = {
        "keyhog": {"backend": "simd", "cache": "off", "daemon": "off", "mode": "full"},
        "betterleaks": {
            "backend": "default",
            "cache": "off",
            "daemon": "off",
            "mode": "no-validate",
        },
        "kingfisher": {
            "backend": "default",
            "cache": "off",
            "daemon": "off",
            "mode": "low-no-validate",
        },
        "trufflehog": {
            "backend": "default",
            "cache": "off",
            "daemon": "off",
            "mode": "no-verify",
        },
        "titus": {
            "backend": "default",
            "cache": "off",
            "daemon": "off",
            "mode": "no-validate",
        },
        "noseyparker": {
            "backend": "default",
            "cache": "off",
            "daemon": "off",
            "mode": "no-git-history",
        },
    }
    return configs[scanner]


def _write_bench_result(results_dir, scanner, category, tp, fn):
    result = {
        "schema_version": "bench-v3",
        "generated_at": "2026-06-19T00:00:00Z",
        "scanner": {
            "name": scanner,
            "version": "test",
            "config": _bench_config(scanner),
        },
        "corpus": {
            "name": "creddata",
            "fixture_count": 10,
            "labeled_positives": tp + fn,
            "bytes": 100,
        },
        "detection": {
            "overall": {"tp": tp, "fp": 0, "fn": fn},
            "per_category": {
                category: {"tp": tp, "fp": 0, "fn": fn},
            },
            "per_detector": {},
        },
        "speed": {"wall_ms": 10.0, "throughput_mb_s": 1.0, "peak_rss_kb": 1024},
        "finding_count": tp,
        "available": True,
    }
    (results_dir / f"{scanner}.json").write_text(
        json.dumps(result),
        encoding="utf-8",
    )


def _write_full_differential(results_dir, category="generic"):
    rows = {
        "keyhog": (1, 2),
        "betterleaks": (3, 0),
        "kingfisher": (2, 1),
        "trufflehog": (1, 2),
        "titus": (1, 2),
        "noseyparker": (0, 3),
    }
    for scanner, (tp, fn) in rows.items():
        _write_bench_result(results_dir, scanner, category, tp, fn)


def test_load_real_corpus_rejects_missing_tail_provenance_before_feature_dump(
    tmp_path,
    monkeypatch,
):
    corpus = tmp_path / "real.jsonl"
    corpus.write_text(
        json.dumps({
            "text": "secret",
            "context": "api_key = secret",
            "label": 1,
            "kind": "real-creddata-pos",
            "source_file": "repo/a.py",
        }) + "\n",
        encoding="utf-8",
    )

    def fail_feature_dump(*_args, **_kwargs):
        raise AssertionError("feature dump must not run for an invalid real corpus")

    monkeypatch.setattr(
        train_classifier.rust_features,
        "compute_feature_matrix",
        fail_feature_dump,
    )
    with pytest.raises(ValueError, match="missing required `class`"):
        train_classifier.load_real_corpus(str(corpus), 42)


def test_load_real_corpus_requires_explicit_class_detector_and_source_file(
    tmp_path,
    monkeypatch,
):
    corpus = tmp_path / "real.jsonl"
    corpus.write_text(
        json.dumps({
            "text": "secret",
            "context": "api_key = secret",
            "label": 1,
            "kind": "real-creddata-pos",
            "class": "authentication-key",
            "detector_id": "generic-api-key",
            "candidate_channel": "pattern",
            "source_file": "repo/a.py",
            "pattern_index": 0,
            "source_role": "structured-assignment-value",
            "context_class": "vendor-pattern",
            "detector_digest": "0123456789abcdef",
        }) + "\n",
        encoding="utf-8",
    )

    def fake_feature_dump(records, _lists, num_features):
        assert [rec["class"] for rec in records] == ["authentication-key"]
        assert [rec["detector_id"] for rec in records] == ["generic-api-key"]
        return np.zeros((len(records), num_features), dtype=np.float32)

    monkeypatch.setattr(
        train_classifier.rust_features,
        "compute_feature_matrix",
        fake_feature_dump,
    )
    X, y, classes, detectors, files, identities = train_classifier.load_real_corpus(
        str(corpus), 42
    )

    assert X.shape == (1, 42)
    assert y.tolist() == [1.0]
    assert classes == ["authentication-key"]
    assert detectors == ["generic-api-key"]
    assert files == ["repo/a.py"]
    assert identities == [{
        "detector_id": "generic-api-key",
        "pattern_index": 0,
        "candidate_channel": "pattern",
        "source_role": "structured-assignment-value",
        "context_class": "vendor-pattern",
        "detector_digest": "0123456789abcdef",
    }]


def test_load_real_corpus_consumes_secret_safe_versioned_features(
    tmp_path,
    monkeypatch,
):
    features = [index / 100.0 for index in range(55)]
    record = {
        "schema_version": "keyhog-ml-feature-corpus-v1",
        "feature_schema_sha256": "ab" * 32,
        "features": features,
        "label": 1,
        "kind": "real-creddata-pos",
        "class": "authentication-key",
        "detector_id": "generic-api-key",
        "candidate_channel": "pattern",
        "source_file": "repo/a.py",
        "pattern_index": 0,
        "source_role": "structured-assignment-value",
        "context_class": "vendor-pattern",
        "detector_digest": "0123456789abcdef",
    }
    corpus = tmp_path / "real.jsonl"
    corpus.write_text(json.dumps(record) + "\n", encoding="utf-8")
    monkeypatch.setattr(
        train_classifier.rust_features,
        "quantized_schema_digest",
        lambda: "ab" * 32,
    )

    X, y, classes, detectors, files, identities = train_classifier.load_real_corpus(
        str(corpus),
        55,
    )

    np.testing.assert_allclose(X[0], np.asarray(features, dtype=np.float32))
    assert y.tolist() == [1.0]
    assert classes == ["authentication-key"]
    assert detectors == ["generic-api-key"]
    assert files == ["repo/a.py"]
    assert identities[0]["pattern_index"] == 0


@pytest.mark.parametrize("unsafe_field", ("text", "context"))
def test_versioned_feature_corpus_rejects_plaintext_fields(unsafe_field, monkeypatch):
    record = {
        "schema_version": "keyhog-ml-feature-corpus-v1",
        "feature_schema_sha256": "ab" * 32,
        "features": [0.0] * 55,
        unsafe_field: "plaintext-must-not-persist",
    }
    monkeypatch.setattr(
        train_classifier.rust_features,
        "quantized_schema_digest",
        lambda: "ab" * 32,
    )
    with pytest.raises(ValueError, match="plaintext text or context"):
        train_classifier.rust_features.compute_feature_matrix(
            [record],
            ((), (), (), ()),
            55,
        )


@pytest.mark.parametrize(
    "missing",
    ("pattern_index", "source_role", "context_class", "detector_digest"),
)
def test_load_real_corpus_rejects_incomplete_calibration_identity(
    tmp_path,
    monkeypatch,
    missing,
):
    record = {
        "text": "secret",
        "context": "api_key = secret",
        "label": 1,
        "kind": "real-creddata-pos",
        "class": "authentication-key",
        "detector_id": "generic-api-key",
        "candidate_channel": "pattern",
        "source_file": "repo/a.py",
        "pattern_index": 0,
        "source_role": "structured-assignment-value",
        "context_class": "vendor-pattern",
        "detector_digest": "0123456789abcdef",
    }
    del record[missing]
    corpus = tmp_path / "real.jsonl"
    corpus.write_text(json.dumps(record) + "\n", encoding="utf-8")
    monkeypatch.setattr(
        train_classifier.rust_features,
        "compute_feature_matrix",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("feature dump must not run")
        ),
    )
    with pytest.raises(ValueError, match=missing):
        train_classifier.load_real_corpus(str(corpus), 55)


def test_contract_training_rows_abstain_from_pattern_calibration():
    assert train_classifier.calibration_identity(
        "contracts.jsonl",
        1,
        {
            "source_file": "contract:generic-password",
            "candidate_channel": "pattern",
        },
    ) is None


def _calibration_identity(pattern=3, role="structured-assignment-value", context="vendor-pattern"):
    return {
        "detector_id": "fixture-detector",
        "pattern_index": pattern,
        "candidate_channel": "pattern",
        "source_role": role,
        "context_class": context,
        "detector_digest": "0123456789abcdef",
    }


def test_pattern_calibration_artifact_has_exact_secret_free_key_and_required_metrics():
    identities = [_calibration_identity() for _ in range(4)]
    artifact = train_classifier.build_pattern_calibration_artifact(
        "moe-v1-0123456789abcdef",
        "0123456789abcdef",
        np.asarray([0.99, 0.98, 0.01, 0.02]),
        np.asarray([0.99, 0.98, 0.01, 0.02]),
        np.asarray([1, 1, 0, 0]),
        identities,
    )

    assert artifact["schema_version"] == 1
    assert (
        artifact["identity_schema"]
        == train_classifier.PATTERN_CALIBRATION_IDENTITY_SCHEMA
    )
    embedded = json.loads(
        (
            train_classifier.REPO_ROOT
            / "crates/scanner/src/pattern_calibration.json"
        ).read_text(encoding="utf-8")
    )
    assert embedded["schema_version"] == artifact["schema_version"]
    assert embedded["identity_schema"] == artifact["identity_schema"]
    assert len(artifact["entries"]) == 1
    entry = artifact["entries"][0]
    assert {
        key: entry[key]
        for key in (
            "detector_id",
            "pattern_index",
            "candidate_channel",
            "source_role",
            "context_class",
        )
    } == {
        key: identities[0][key]
        for key in (
            "detector_id",
            "pattern_index",
            "candidate_channel",
            "source_role",
            "context_class",
        )
    }
    assert set(entry["metrics"]) == {
        "f1",
        "precision",
        "recall",
        "recall_at_blocking_floor",
        "brier_score",
        "ece",
        "positive_support",
        "negative_support",
    }
    def field_names(value):
        if isinstance(value, dict):
            for key, child in value.items():
                yield key
                yield from field_names(child)
        elif isinstance(value, list):
            for child in value:
                yield from field_names(child)

    forbidden = {"text", "context", "credential", "value", "source_file"}
    assert forbidden.isdisjoint(field_names(artifact))
    assert "context_class" in set(field_names(artifact))


def test_pattern_calibration_separates_unsupported_exact_keys_and_missing_classes():
    identities = [
        _calibration_identity(),
        _calibration_identity(pattern=4),
        _calibration_identity(role="string-literal"),
        _calibration_identity(context="test-fixture"),
    ]
    entries = train_classifier.pattern_calibration_entries(
        np.asarray([0.99, 0.99, 0.01, 0.01]),
        np.asarray([0.99, 0.99, 0.01, 0.01]),
        np.asarray([1, 1, 0, 0]),
        identities,
    )

    assert len(entries) == 4
    assert all(
        entry["metrics"]["positive_support"] == 0
        or entry["metrics"]["negative_support"] == 0
        for entry in entries
    )


def test_pattern_calibration_rejects_float_quantized_verdict_drift():
    identities = [_calibration_identity() for _ in range(4)]
    with pytest.raises(ValueError, match="float/quantized verdict parity"):
        train_classifier.pattern_calibration_entries(
            np.asarray([0.99, 0.98, 0.01, 0.02]),
            np.asarray([0.49, 0.98, 0.01, 0.02]),
            np.asarray([1, 1, 0, 0]),
            identities,
        )


def test_pattern_calibration_metrics_expose_recall_brier_and_ece_regressions():
    identities = [_calibration_identity() for _ in range(4)]
    entries = train_classifier.pattern_calibration_entries(
        np.asarray([0.39, 0.99, 0.90, 0.90]),
        np.asarray([0.39, 0.99, 0.90, 0.90]),
        np.asarray([1, 1, 0, 0]),
        identities,
    )
    metrics = entries[0]["metrics"]
    assert metrics["recall_at_blocking_floor"] == 0.5
    assert metrics["brier_score"] > 0.25
    assert metrics["ece"] > 0.1


def test_real_eval_reports_per_class_truth():
    metrics = train_classifier.real_eval(
        np.asarray([0.90, 0.20, 0.60, 0.30, 0.45], dtype=np.float32),
        np.asarray([1, 1, 0, 1, 0], dtype=np.float32),
        ["aws", "aws", "aws", "git", "noise"],
        [
            "aws-access-key",
            "aws-access-key",
            "entropy-api-key",
            "github-classic-pat",
            "entropy-api-key",
        ],
    )

    assert metrics["real_pos_recall_at_0.40_floor"] == 0.3333
    assert metrics["per_class"]["aws"] == {
        "n_test": 3,
        "n_pos": 2,
        "n_neg": 1,
        "tp": 1,
        "fp": 1,
        "fn": 1,
        "precision": 0.5,
        "recall": 0.5,
        "f1": 0.5,
        "recall_at_0_40_floor": 0.5,
    }
    assert metrics["per_class"]["git"]["recall_at_0_40_floor"] == 0.0
    assert metrics["per_class"]["noise"]["recall_at_0_40_floor"] is None
    assert metrics["per_detector"]["aws-access-key"]["recall_at_0_40_floor"] == 0.5
    assert metrics["per_detector"]["entropy-api-key"]["n_neg"] == 2
    assert metrics["per_recall_sensitive_class"] == {
        "aws": {
            "n_test": 1,
            "n_pos": 0,
            "n_neg": 1,
            "tp": 0,
            "fp": 1,
            "fn": 0,
            "precision": 0.0,
            "recall": 0.0,
            "f1": 0.0,
            "recall_at_0_40_floor": None,
        },
        "noise": {
            "n_test": 1,
            "n_pos": 0,
            "n_neg": 1,
            "tp": 0,
            "fp": 0,
            "fn": 0,
            "precision": 0.0,
            "recall": 0.0,
            "f1": 0.0,
            "recall_at_0_40_floor": None,
        },
    }

    summary = train_classifier.real_metric_summary(metrics)
    assert summary["recall_sensitive_detectors"] == {}
    assert summary["zero_recall_detectors"] == ["github-classic-pat"]
    assert "per_class" not in summary


def test_per_class_gate_rejects_weak_tail_and_baseline_regression(tmp_path):
    baseline = tmp_path / "model_card.json"
    baseline.write_text(
        json.dumps({
            "metrics": {
                "real_heldout": {
                    "per_recall_sensitive_class": {
                        "aws": {"n_pos": 2, "recall_at_0_40_floor": 0.75}
                    }
                }
            }
        }),
        encoding="utf-8",
    )
    args = types.SimpleNamespace(
        write=True,
        baseline_model_card=str(baseline),
        min_real_class_recall=0.50,
        min_real_class_support=1,
        max_real_class_recall_drop=0.0,
    )

    message = train_classifier.per_class_gate_error(
        {
            "per_recall_sensitive_class": {
                "aws": {"n_pos": 2, "recall_at_0_40_floor": 0.50},
                "git": {"n_pos": 1, "recall_at_0_40_floor": 0.0},
            }
        },
        args,
    )

    assert "git recall@0.40=0.0000 < floor 0.5000" in message
    assert "aws recall@0.40 dropped 0.7500->0.5000" in message


def test_per_detector_gate_rejects_hidden_detector_hole_and_regression(tmp_path):
    baseline = tmp_path / "model_card.json"
    baseline.write_text(
        json.dumps({
            "metrics": {
                "real_heldout": {
                    "per_detector": {
                        "entropy-generic": {
                            "n_pos": 4,
                            "recall_at_0_40_floor": 0.75,
                        }
                    }
                }
            }
        }),
        encoding="utf-8",
    )
    args = types.SimpleNamespace(
        write=True,
        baseline_model_card=str(baseline),
        min_real_detector_recall=0.50,
        min_real_detector_support=1,
        min_real_detector_negative_support=1,
        max_real_detector_recall_drop=0.0,
    )

    message = train_classifier.per_detector_gate_error(
        {
            "per_detector": {
                "entropy-generic": {
                    "n_pos": 4,
                    "n_neg": 1,
                    "recall_at_0_40_floor": 0.50,
                },
                "entropy-api-key": {
                    "n_pos": 1,
                    "n_neg": 1,
                    "recall_at_0_40_floor": 0.0,
                },
            }
        },
        args,
    )

    assert "entropy-api-key recall@0.40=0.0000 < floor 0.5000" in message
    assert "entropy-generic recall@0.40 dropped 0.7500->0.5000" in message


def test_per_detector_gate_rejects_unmeasured_authoritative_channel():
    args = types.SimpleNamespace(
        write=False,
        baseline_model_card="unused.json",
        min_real_detector_recall=0.50,
        min_real_detector_support=1,
        min_real_detector_negative_support=1,
        max_real_detector_recall_drop=0.0,
    )
    message = train_classifier.per_detector_gate_error(
        {
            "per_detector": {
                detector_id: {
                    "n_pos": 1,
                    "n_neg": 1,
                    "recall_at_0_40_floor": 1.0,
                }
                for detector_id in (
                    "entropy-api-key",
                    "entropy-password",
                    "entropy-token",
                )
            }
            | {
                "entropy-generic": {
                    "n_pos": 3,
                    "n_neg": 0,
                    "recall_at_0_40_floor": 1.0,
                }
            }
        },
        args,
    )
    assert "entropy-generic has 0 negative held-out candidate(s), requires 1" in message


def test_detector_balancing_uses_only_train_split_and_respects_cap():
    combined_labels = np.asarray([1, 1, 1, 0, 0, 0, 1], dtype=np.float32)
    weights = train_classifier.detector_balanced_sample_weights(
        combined_labels=combined_labels,
        combined_train_indices=np.asarray([0, 1, 2, 3, 4, 5]),
        combined_detectors=[
            "github-classic-pat",
            "github-classic-pat",
            "entropy-api-key",
            "entropy-api-key",
            "entropy-api-key",
            "entropy-api-key",
            "entropy-api-key",
        ],
        max_multiplier=2.0,
    )

    assert weights.tolist() == [1.0, 1.0, 2.0, 1.0, 1.0, 1.0, 1.0]
    with pytest.raises(ValueError, match="finite and >= 1.0"):
        train_classifier.detector_balanced_sample_weights(
            combined_labels,
            np.asarray([0]),
            ["detector"],
            0.5,
        )


def test_detector_balancing_does_not_reweight_lift_only_detectors():
    weights = train_classifier.detector_balanced_sample_weights(
        combined_labels=np.asarray([1, 0, 0, 0], dtype=np.float32),
        combined_train_indices=np.asarray([0, 1, 2, 3]),
        combined_detectors=["github-classic-pat"] * 4,
        max_multiplier=8.0,
    )

    assert weights.tolist() == [1.0, 1.0, 1.0, 1.0]


def test_recall_sensitive_class_balancing_uses_only_training_positives():
    weights = train_classifier.recall_sensitive_class_sample_weights(
        combined_length=7,
        real_offset=1,
        real_labels=np.asarray([1, 1, 1, 1, 1, 0], dtype=np.float32),
        real_classes=["common", "common", "common", "rare", "heldout", "rare"],
        real_detectors=["entropy-api-key"] * 6,
        real_train_indices=np.asarray([0, 1, 2, 3, 5]),
        max_multiplier=2.0,
    )

    assert weights.tolist() == [1.0, 1.0, 1.0, 1.0, 2.0, 1.0, 1.0]


def test_checkpoint_selection_prioritizes_shipping_class_recall_gate():
    labels = np.asarray([1, 1, 1, 1, 0, 0], dtype=np.float32)
    groups = np.asarray(["rare", "rare", "common", "common", "rare", "common"])
    aggregate_favored = np.asarray([0.1, 0.1, 0.9, 0.9, 0.1, 0.1])
    gate_safe = np.asarray([0.6, 0.6, 0.6, 0.6, 0.3, 0.3])

    assert train_classifier.validation_selection_key(
        gate_safe, labels, groups
    ) > train_classifier.validation_selection_key(
        aggregate_favored, labels, groups
    )


def test_checkpoint_selection_keeps_real_precision_and_f1_floors_primary():
    labels = np.asarray([1] * 10 + [0] * 20, dtype=np.float32)
    groups = np.asarray(["rare"] * 2 + ["common"] * 28)
    real_mask = np.ones(len(labels), dtype=bool)
    class_safe_but_imprecise = np.asarray([0.9] * 30)
    aggregate_safe_with_class_gap = np.asarray([0.1] * 2 + [0.9] * 8 + [0.1] * 20)

    assert train_classifier.validation_selection_key(
        aggregate_safe_with_class_gap, labels, groups, real_mask
    ) > train_classifier.validation_selection_key(
        class_safe_but_imprecise, labels, groups, real_mask
    )


def test_warm_start_checkpoint_cannot_regress_initial_real_metrics():
    labels = np.asarray([1] * 10 + [0] * 20, dtype=np.float32)
    groups = np.asarray(["rare"] * 2 + ["common"] * 28)
    real_mask = np.ones(len(labels), dtype=bool)
    baseline = np.asarray([0.9] * 8 + [0.1] * 2 + [0.1] * 20)
    baseline_f1, baseline_precision, _ = train_classifier.prf(baseline, labels, 0.5)
    recall_favored_regression = np.asarray([0.9] * 10 + [0.9] * 10 + [0.1] * 10)
    floors = (baseline_f1, baseline_precision)

    assert train_classifier.validation_selection_key(
        baseline, labels, groups, real_mask, floors
    ) > train_classifier.validation_selection_key(
        recall_favored_regression, labels, groups, real_mask, floors
    )


def test_six_scanner_differential_attaches_full_class_comparison(tmp_path):
    results_dir = tmp_path / "results"
    results_dir.mkdir()
    _write_full_differential(results_dir)
    args = types.SimpleNamespace(
        differential_results=str(results_dir),
        differential_corpus="creddata",
    )

    comparison = train_classifier.six_scanner_differential_comparison(
        {
            "per_class": {
                "generic": {
                    "n_pos": 2,
                    "recall_at_0_40_floor": 0.5,
                }
            }
        },
        args,
    )

    klass = comparison["classes"]["generic"]
    assert comparison["scanner_count"] == 6
    assert comparison["compared_class_count"] == 1
    assert klass["benchmark_best_competitor"]["scanner"] == "betterleaks"
    assert klass["benchmark_recall_gap"] == 0.6667
    assert set(klass["benchmark_competitors"]) == {
        "betterleaks",
        "kingfisher",
        "trufflehog",
        "titus",
        "noseyparker",
    }


def test_six_scanner_differential_rejects_missing_class(tmp_path):
    results_dir = tmp_path / "results"
    results_dir.mkdir()
    _write_full_differential(results_dir, category="generic")
    args = types.SimpleNamespace(
        differential_results=str(results_dir),
        differential_corpus="creddata",
    )

    with pytest.raises(ValueError, match="missing positive held-out class"):
        train_classifier.six_scanner_differential_comparison(
            {
                "per_class": {
                    "aws": {
                        "n_pos": 1,
                        "recall_at_0_40_floor": 1.0,
                    }
                }
            },
            args,
        )


def test_group_split_forces_contract_files_into_train():
    # Contract fixtures (source_file="contract:<det>") must ALWAYS train and never
    # enter the held-out, the contract gate tests the full suite, so they are a
    # memorization requirement, not a generalization target.
    files = (
        [f"repo/real_{i}.py" for i in range(10)]
        + ["contract:generic-password", "contract:aws-access-key", "contract:github-pat"]
    )
    tr, va, te = train_classifier._group_split(files, seed=7)
    contract_idx = {i for i, f in enumerate(files) if f.startswith("contract:")}
    assert contract_idx <= set(tr.tolist())
    assert not (contract_idx & set(va.tolist()))
    assert not (contract_idx & set(te.tolist()))
    # real files still populate a non-empty held-out (honest generalisation)
    assert len(va) > 0 and len(te) > 0
    # complete + disjoint partition over every record index
    assert sorted(tr.tolist() + va.tolist() + te.tolist()) == list(range(len(files)))


def test_group_split_is_noop_without_contracts():
    # Backward-compat: with no contract files the split is the plain 70/15/15
    # grouping (my contract-force change must not perturb ordinary training).
    files = [f"repo/f_{i}.py" for i in range(20)]
    tr, va, te = train_classifier._group_split(files, seed=3)
    assert sorted(tr.tolist() + va.tolist() + te.tolist()) == list(range(20))
    assert (len(tr), len(va), len(te)) == (14, 3, 3)


def test_real_corpus_model_card_requires_six_scanner_differential(tmp_path):
    args = types.SimpleNamespace(
        write=False,
        real_corpus="real.jsonl",
        corpus=str(tmp_path / "corpus.jsonl"),
        out=str(tmp_path / "weights.bin"),
        features=42,
    )

    with pytest.raises(SystemExit, match="six-scanner"):
        train_classifier.write_model_card(
            b"weights",
            b"quantized",
            "0" * 64,
            args,
            {"f1": 1.0, "precision": 1.0, "recall": 1.0},
            {
                "recall_at_0_40_floor": 1.0,
                "per_class": {"generic": {"n_pos": 1}},
                "per_detector": {"generic": {"n_pos": 1}},
            },
        )


def test_pattern_calibration_model_card_summary_is_honest_when_abstaining():
    artifact = train_classifier.build_pattern_calibration_artifact(
        "moe-v1-0123456789abcdef",
        None,
        np.asarray([]),
        np.asarray([]),
        np.asarray([]),
        [],
    )

    summary = train_classifier.pattern_calibration_model_card_summary(artifact)

    assert summary["status"] == "abstaining"
    assert summary["entry_count"] == 0
    assert summary["eligible_entry_count"] == 0
    assert summary["aggregate_metrics"] == {
        "positive_support": 0,
        "negative_support": 0,
        "minimum_recall": None,
        "minimum_recall_at_blocking_floor": None,
        "maximum_brier_score": None,
        "maximum_ece": None,
    }
    assert summary["artifact_sha256"] == hashlib.sha256(
        train_classifier.serialize_pattern_calibration_artifact(artifact)
    ).hexdigest()


def test_pattern_calibration_model_card_summary_aggregates_without_key_payloads():
    identities = [_calibration_identity() for _ in range(4)]
    artifact = train_classifier.build_pattern_calibration_artifact(
        "moe-v1-0123456789abcdef",
        "0123456789abcdef",
        np.asarray([0.99, 0.98, 0.01, 0.02]),
        np.asarray([0.99, 0.98, 0.01, 0.02]),
        np.asarray([1.0, 1.0, 0.0, 0.0]),
        identities,
    )

    summary = train_classifier.pattern_calibration_model_card_summary(artifact)
    serialized = json.dumps(summary, sort_keys=True)

    assert summary["status"] == "calibrated"
    assert summary["entry_count"] == 1
    assert summary["eligible_entry_count"] == 1
    assert summary["aggregate_metrics"]["positive_support"] == 2
    assert summary["aggregate_metrics"]["negative_support"] == 2
    for unsafe_identity in (
        "fixture-detector",
        "structured-assignment-value",
        "vendor-pattern",
    ):
        assert unsafe_identity not in serialized
