import json
import types

import numpy as np

import train_classifier


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
