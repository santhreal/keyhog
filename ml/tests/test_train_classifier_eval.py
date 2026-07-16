import json
import types

import numpy as np
import pytest

import train_classifier


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
            "source_file": "repo/a.py",
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
    X, y, classes, detectors, files = train_classifier.load_real_corpus(str(corpus), 42)

    assert X.shape == (1, 42)
    assert y.tolist() == [1.0]
    assert classes == ["authentication-key"]
    assert detectors == ["generic-api-key"]
    assert files == ["repo/a.py"]


def test_real_eval_reports_per_class_truth():
    metrics = train_classifier.real_eval(
        np.asarray([0.90, 0.20, 0.60, 0.30, 0.45], dtype=np.float32),
        np.asarray([1, 1, 0, 1, 0], dtype=np.float32),
        ["aws", "aws", "aws", "git", "noise"],
        ["aws-access-key", "aws-access-key", "generic", "github-pat", "generic"],
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
    assert metrics["per_detector"]["generic"]["n_neg"] == 2


def test_per_class_gate_rejects_weak_tail_and_baseline_regression(tmp_path):
    baseline = tmp_path / "model_card.json"
    baseline.write_text(
        json.dumps({
            "metrics": {
                "real_heldout": {
                    "per_class": {
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
            "per_class": {
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
                        "generic-secret": {
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
        max_real_detector_recall_drop=0.0,
    )

    message = train_classifier.per_detector_gate_error(
        {
            "per_detector": {
                "generic-secret": {
                    "n_pos": 4,
                    "recall_at_0_40_floor": 0.50,
                },
                "stripe-secret-key": {
                    "n_pos": 1,
                    "recall_at_0_40_floor": 0.0,
                },
            }
        },
        args,
    )

    assert "stripe-secret-key recall@0.40=0.0000 < floor 0.5000" in message
    assert "generic-secret recall@0.40 dropped 0.7500->0.5000" in message


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
            args,
            {"f1": 1.0, "precision": 1.0, "recall": 1.0},
            {
                "recall_at_0_40_floor": 1.0,
                "per_class": {"generic": {"n_pos": 1}},
                "per_detector": {"generic": {"n_pos": 1}},
            },
        )
