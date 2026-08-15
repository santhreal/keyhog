import dataclasses
import sys
import json

import numpy as np

import pytest

import harvest_corpus
from bench.corpora.base import LabeledRecord
from bench.scanners.keyhog import _normalize_keyhog


def _record(record_id, secret, label, category, ignore=False, file_path="fixture.env"):
    return LabeledRecord(
        id=record_id,
        secret=secret,
        label=label,
        category=category,
        file_path=file_path,
        ignore=ignore,
    )


def _provenance(**overrides):
    provenance = {
        "schema_version": 1,
        "detector_digest": "0123456789abcdef",
        "pattern_index": 3,
        "candidate_channel": "pattern",
        "source_role": "structured-assignment-value",
        "context_class": "vendor-pattern",
    }
    provenance.update(overrides)
    return {"tier": "likely", "reason_code": "vendor-pattern", "provenance": provenance}


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


def test_pattern_provenance_requires_exact_authoritative_identity():
    finding = {"evidence": _provenance()}
    assert harvest_corpus._finding_pattern_provenance(finding, "fixture") == {
        "detector_digest": "0123456789abcdef",
        "pattern_index": 3,
        "candidate_channel": "pattern",
        "source_role": "structured-assignment-value",
        "context_class": "vendor-pattern",
    }

    for missing in (
        "schema_version",
        "detector_digest",
        "pattern_index",
        "candidate_channel",
        "source_role",
        "context_class",
    ):
        provenance = _provenance()
        del provenance["provenance"][missing]
        with pytest.raises(ValueError, match="evidence.provenance"):
            harvest_corpus._finding_pattern_provenance(
                {"evidence": provenance},
                "fixture",
            )

    with pytest.raises(ValueError, match="candidate_channel must be 'pattern'"):
        harvest_corpus._finding_pattern_provenance(
            {"evidence": _provenance(candidate_channel="entropy")},
            "fixture",
        )


def test_keyhog_normalization_preserves_evidence_provenance():
    evidence = _provenance()
    findings = _normalize_keyhog(
        [
            {
                "credential": "fixture-secret",
                "detector_id": "generic-api-key",
                "confidence": 0.75,
                "location": {
                    "file_path": "fixture.env",
                    "line": 1,
                    "offset": 0,
                },
                "evidence": evidence,
            }
        ]
    )
    assert findings[0]["evidence"] == evidence


def test_harvest_emits_versioned_secret_safe_features_with_exact_identity(
    tmp_path,
    monkeypatch,
):
    secret = "fixture-secret-that-must-not-persist"
    fixture = tmp_path / "fixture.env"
    fixture.write_text(f"API_KEY={secret}\n", encoding="utf-8")

    @dataclasses.dataclass
    class FakeConfig:
        min_confidence: float = 0.5

    class FakeCorpus:
        file_root = tmp_path
        scan_root = tmp_path

        def records(self):
            return [
                _record(
                    "positive",
                    secret,
                    True,
                    "authentication-key",
                )
            ]

    class FakeScanner:
        binary = "keyhog"

        def available(self):
            return True

        def default_config(self):
            return FakeConfig()

        def run(self, _root, _cfg):
            return (
                [
                    {
                        "file": str(fixture),
                        "line": 1,
                        "value": secret,
                        "detector": "generic-api-key",
                        "evidence": _provenance(),
                    }
                ],
                object(),
            )

    def fake_features(records, _lists, width):
        assert width == 55
        assert records[0]["text"] == secret
        assert secret in records[0]["context"]
        return np.asarray([[index / 100.0 for index in range(width)]], dtype=np.float32)

    monkeypatch.setattr(harvest_corpus, "resolve_corpus", lambda _name: FakeCorpus())
    monkeypatch.setattr(
        harvest_corpus,
        "resolve_scanner",
        lambda *_args, **_kwargs: FakeScanner(),
    )
    monkeypatch.setattr(
        harvest_corpus.rust_features,
        "compute_feature_matrix",
        fake_features,
    )
    monkeypatch.setattr(
        harvest_corpus.rust_features,
        "quantized_schema_digest",
        lambda: "ab" * 32,
    )

    rows = harvest_corpus.harvest("fixture", None, 0.0)
    assert len(rows) == 1
    row = rows[0]
    assert row["schema_version"] == "keyhog-ml-feature-corpus-v1"
    assert row["feature_schema_sha256"] == "ab" * 32
    assert len(row["features"]) == 55
    assert {
        key: row[key]
        for key in (
            "detector_id",
            "detector_digest",
            "pattern_index",
            "candidate_channel",
            "source_role",
            "context_class",
        )
    } == {
        "detector_id": "generic-api-key",
        "detector_digest": "0123456789abcdef",
        "pattern_index": 3,
        "candidate_channel": "pattern",
        "source_role": "structured-assignment-value",
        "context_class": "vendor-pattern",
    }
    serialized = json.dumps(row)
    assert secret not in serialized
    assert "text" not in row
    assert "context" not in row


def test_harvest_rejects_ambiguous_finding_paths(tmp_path, monkeypatch):
    @dataclasses.dataclass
    class FakeConfig:
        min_confidence: float = 0.5

    class FakeCorpus:
        name = "fake"
        file_root = tmp_path
        scan_root = tmp_path

        def records(self):
            return [
                _record(
                    "left",
                    "left-secret",
                    True,
                    "left",
                    file_path="left/fixture.env",
                ),
                _record(
                    "right",
                    "right-secret",
                    True,
                    "right",
                    file_path="right/fixture.env",
                ),
            ]

    class FakeScanner:
        binary = "keyhog"

        def available(self):
            return True

        def default_config(self):
            return FakeConfig()

        def run(self, _root, _cfg):
            return ([{"file": "fixture.env", "value": "left-secret"}], object())

    monkeypatch.setattr(harvest_corpus, "resolve_corpus", lambda _name: FakeCorpus())
    monkeypatch.setattr(
        harvest_corpus,
        "resolve_scanner",
        lambda *_args, **_kwargs: FakeScanner(),
    )

    with pytest.raises(ValueError, match="ambiguous finding path matched 2 corpus files"):
        harvest_corpus.harvest("fake", None, 0.0)


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
