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
    assert harvest_corpus.classify_finding(records, "YOUR_API_KEY_HERE") == (
        0,
        "authentication-key",
        True,
    )
    assert harvest_corpus.classify_finding(records, "not-the-secret") == (
        0,
        "authentication-key",
        False,
    )
