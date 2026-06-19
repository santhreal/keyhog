import sys

import pytest

import harvest_corpus
from bench.corpora.base import LabeledRecord


def _record(record_id, secret, label, category, ignore=False):
    return LabeledRecord(
        id=record_id,
        secret=secret,
        label=label,
        category=category,
        file_path="fixture.env",
        ignore=ignore,
    )


def test_classify_finding_preserves_scorer_category_and_ignore_semantics():
    records = [
        _record("pos", "AKIAQYLPMN5HFIQR7XYA", True, "authentication-key"),
        _record("template", "YOUR_API_KEY_HERE", False, "fixture", ignore=True),
    ]

    assert harvest_corpus.classify_finding(records, "AKIAQYLPMN5HFIQR7XYA") == (
        1,
        "authentication-key",
        False,
    )
    label, _secret_class, ignored = harvest_corpus.classify_finding(
        records,
        "YOUR_API_KEY_HERE",
    )
    assert (label, ignored) == (0, True)
    assert harvest_corpus.classify_finding(records, "not-the-secret") == (
        0,
        "authentication-key",
        False,
    )


def test_classify_finding_rejects_unknown_provenance_labels():
    with pytest.raises(ValueError, match="positive record pos: missing explicit class"):
        harvest_corpus.classify_finding(
            [_record("pos", "AKIAQYLPMN5HFIQR7XYA", True, "unknown")],
            "AKIAQYLPMN5HFIQR7XYA",
            "creddata:fixture.env",
        )

    with pytest.raises(ValueError, match="false-positive file: missing explicit class"):
        harvest_corpus.classify_finding(
            [_record("neg", "", False, "unknown")],
            "not-the-secret",
            "creddata:fixture.env",
        )


def test_finding_detector_id_rejects_unknown_or_missing_values():
    assert harvest_corpus._finding_detector_id(
        {"detector": "aws-access-key"},
        "creddata:fixture.env",
    ) == "aws-access-key"
    assert harvest_corpus._finding_detector_id(
        {"detector_id": "github-classic-pat"},
        "creddata:fixture.env",
    ) == "github-classic-pat"
    assert harvest_corpus._finding_detector_id(
        {"detector": "unknown", "detector_id": "github-classic-pat"},
        "creddata:fixture.env",
    ) == "github-classic-pat"

    for finding in (
        {},
        {"detector": "unknown"},
        {"detector_id": " "},
        {"detector": "n/a"},
    ):
        with pytest.raises(ValueError, match="missing explicit detector_id"):
            harvest_corpus._finding_detector_id(finding, "creddata:fixture.env")


def test_main_fails_closed_without_writing_when_requested_corpus_fails(
    tmp_path,
    monkeypatch,
    capsys,
):
    out = tmp_path / "real_corpus.jsonl"

    def fake_harvest(name, _keyhog_bin, _floor):
        if name == "bad":
            raise RuntimeError("boom")
        return [
            {
                "text": "secret",
                "context": "api_key = secret",
                "label": 1,
                "kind": "real-good-pos",
                "class": "authentication-key",
                "detector_id": "generic-api-key",
                "source_file": "repo/a.py",
            }
        ]

    monkeypatch.setattr(harvest_corpus, "harvest", fake_harvest)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "harvest_corpus.py",
            "--corpora",
            "good",
            "bad",
            "--out",
            str(out),
        ],
    )

    assert harvest_corpus.main() == 1
    assert not out.exists()
    captured = capsys.readouterr()
    assert "[bad] harvest FAILED: boom" in captured.err
    assert "not writing real-corpus output" in captured.err
