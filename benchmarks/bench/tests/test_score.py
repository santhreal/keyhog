import pathlib

from bench.corpora.base import LabeledRecord
from bench.score import overlap, score


def _record(record_id: str, secret: str, label: bool, file_path: str, category: str = "api"):
    return LabeledRecord(
        id=record_id,
        secret=secret,
        label=label,
        category=category,
        file_path=file_path,
    )


def test_overlap_matches_containment_escapes_and_base64():
    assert overlap("secret", "prefix-secret-suffix")
    assert overlap("line1\\nline2", "line1\nline2")
    assert overlap("c2VjcmV0LXZhbHVl", "secret-value")
    assert not overlap("alpha", "omega")


def test_score_counts_tp_fp_fn_and_ignore_records(tmp_path: pathlib.Path):
    root = tmp_path
    records = [
        _record("tp", "AKIAQYLPMN5HFIQR7XYA", True, "positive.env", "aws"),
        _record("fn", "sk-live-missing", True, "missing.env", "openai"),
        _record("tn", "not-a-secret", False, "negative.env", "noise"),
        LabeledRecord(
            id="ignore",
            secret="PLACEHOLDER",
            label=False,
            category="fixture",
            file_path="ignored.env",
            ignore=True,
        ),
    ]
    findings = [
        {"file": str(root / "positive.env"), "value": "AWS_ACCESS_KEY_ID=AKIAQYLPMN5HFIQR7XYA"},
        {"file": str(root / "negative.env"), "value": "not-a-secret"},
        {"file": str(root / "ignored.env"), "value": "PLACEHOLDER"},
        {"file": str(root / "unknown.env"), "value": "loose-finding"},
    ]

    result = score(records, findings, root)

    assert result.overall.tp == 1
    assert result.overall.fp == 2
    assert result.overall.fn == 1
    assert result.per_category["noise"].fp == 1
    assert result.per_category["unknown"].fp == 1
    assert "fixture" not in result.per_category
