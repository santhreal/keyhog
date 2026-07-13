import pathlib

import pytest

from bench.corpora.base import LabeledRecord
from bench.score import (
    _build_file_index,
    _resolve_finding_file,
    _resolve_finding_file_candidates,
    build_basename_index,
    overlap,
    score,
)


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


def test_exact_recovery_records_reject_encoded_or_containing_values(tmp_path):
    record = LabeledRecord(
        id="recovered",
        secret="secret-value",
        label=True,
        category="recovery/p01-base64",
        file_path="sample.js",
        match_mode="exact",
    )

    encoded = score(
        [record],
        [{"file": "sample.js", "value": "c2VjcmV0LXZhbHVl"}],
        tmp_path,
    )
    containing = score(
        [record],
        [{"file": "sample.js", "value": "prefix-secret-value-suffix"}],
        tmp_path,
    )
    exact = score(
        [record],
        [{"file": "sample.js", "value": "secret-value"}],
        tmp_path,
    )

    assert (encoded.overall.tp, encoded.overall.fp, encoded.overall.fn) == (0, 1, 1)
    assert (containing.overall.tp, containing.overall.fp, containing.overall.fn) == (0, 1, 1)
    assert (exact.overall.tp, exact.overall.fp, exact.overall.fn) == (1, 0, 0)


def test_labeled_record_rejects_unknown_match_contract():
    with pytest.raises(ValueError, match="unsupported match_mode"):
        LabeledRecord(
            id="bad-contract",
            secret="secret-value",
            label=True,
            category="recovery",
            file_path="sample.js",
            match_mode="contains",
        )


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


def test_shortened_path_attribution_requires_unique_corpus_match(tmp_path: pathlib.Path):
    root = tmp_path
    records = [
        _record("left", "left-secret", True, "left/config.env", "left"),
        _record("right", "right-secret", True, "right/config.env", "right"),
        _record("unique", "unique-secret", True, "nested/unique.env", "unique"),
    ]

    unique = score(
        records,
        [{"file": "unique.env", "value": "unique-secret"}],
        root,
    )
    assert unique.overall.tp == 1
    assert unique.per_category["unique"].tp == 1

    ambiguous = score(
        records,
        [{"file": "config.env", "value": "left-secret"}],
        root,
    )
    assert ambiguous.overall.tp == 0
    assert ambiguous.overall.fn == 3
    assert ambiguous.overall.fp == 1
    assert ambiguous.per_category["unknown"].fp == 1
    assert ambiguous.per_category["left"].fn == 1
    assert ambiguous.per_category["right"].fn == 1


def test_full_path_with_no_record_resolves_empty_not_same_basename(tmp_path: pathlib.Path):
    """A finding path that carries directory structure but matches no record
    must resolve to ZERO candidates (an unlabeled file → skip), NOT to every
    record sharing its basename. The same-basename fallback returning the whole
    basename set for a full path is what crashed `ml/harvest_corpus.py`'s
    exact-path guard on CredData, where 60+ files share `b3356305.md` and one
    lives in a snapshot whose other files ARE labeled, the finding on the
    unlabeled file spuriously "matched 69 corpus files". Regression for the
    harvest ambiguous-path crash."""
    records = [
        _record("a", "sa", True, "data/aaa/_/dup.md", "cat"),
        _record("b", "sb", True, "data/bbb/_/dup.md", "cat"),
        _record("c", "sc", True, "data/ccc/_/dup.md", "cat"),
        _record("u", "su", True, "data/ddd/_/unique.md", "cat"),
    ]
    by_key, aliases = _build_file_index(records, tmp_path)
    bi = build_basename_index(aliases)

    # (1) full path (has "/") into an UNLABELED sibling → empty, not 3.
    unlabeled = _resolve_finding_file_candidates("data/zzz/_/dup.md", aliases, bi)
    assert unlabeled == set(), f"unlabeled full path must skip, got {len(unlabeled)}"
    assert _resolve_finding_file("data/zzz/_/dup.md", aliases, bi) is None

    # (2) an EXACT labeled full path still resolves to precisely its one record.
    hit = _resolve_finding_file_candidates("data/bbb/_/dup.md", aliases, bi)
    assert hit == {str(tmp_path / "data/bbb/_/dup.md")}

    # (3) a partial "/"-anchored suffix that uniquely tails one record resolves.
    suffix = _resolve_finding_file_candidates("ddd/_/unique.md", aliases, bi)
    assert suffix == {str(tmp_path / "data/ddd/_/unique.md")}

    # (4) a BARE basename (no "/") keeps the same-basename fallback so a
    #     basename-only scanner still gets its ambiguity guard (3 dup.md records).
    bare = _resolve_finding_file_candidates("dup.md", aliases, bi)
    assert len(bare) == 3, f"bare-basename fallback must survive, got {len(bare)}"
    assert _resolve_finding_file("dup.md", aliases, bi) is None  # ambiguous → None


def test_per_category_tp_fn_split_and_conservation(tmp_path: pathlib.Path):
    # Ported from the retired tools/secretbench/scoring/test_attribution.py
    # ::test_per_category_split: the per-category TP/FN split plus the
    # conservation invariant (every overall cell is exactly the sum of its
    # per-category cells), which the other score tests don't assert.
    root = tmp_path
    records = [
        _record("auth_tp", "AKIAQYLPMN5HFIQR7XYA", True, "auth.env", "auth"),
        _record("cloud_fn", "ya29.cloud-token-missing", True, "cloud.env", "cloud"),
    ]
    findings = [
        {"file": str(root / "auth.env"), "value": "AKIAQYLPMN5HFIQR7XYA"},
    ]

    result = score(records, findings, root)

    assert result.per_category["auth"].tp == 1
    assert result.per_category["auth"].fn == 0
    assert result.per_category["cloud"].tp == 0
    assert result.per_category["cloud"].fn == 1
    # Conservation: overall == sum over categories, cell by cell.
    assert sum(o.tp for o in result.per_category.values()) == result.overall.tp == 1
    assert sum(o.fn for o in result.per_category.values()) == result.overall.fn == 1


def test_per_detector_tp_fp_unique_and_confidence_histograms(tmp_path: pathlib.Path):
    root = tmp_path
    records = [
        _record("r1", "AKIAQYLPMN5HFIQR7XYA", True, "a.env", "aws"),
        _record("r2", "ghp_aaaaaaaaaaaaaaaaaaaa", True, "b.env", "github"),
    ]
    findings = [
        # r1 caught by two detectors -> not unique to either; tp credited to both.
        {"file": str(root / "a.env"), "value": "AKIAQYLPMN5HFIQR7XYA",
         "detector": "aws-access-key", "confidence": 0.92},
        {"file": str(root / "a.env"), "value": "AKIAQYLPMN5HFIQR7XYA",
         "detector": "generic-high-entropy-string", "confidence": 0.55},
        # r2 caught only by github-pat -> unique_tp for it.
        {"file": str(root / "b.env"), "value": "ghp_aaaaaaaaaaaaaaaaaaaa",
         "detector": "github-pat", "confidence": 0.99},
        # false fire from the noisy generic detector at low confidence.
        {"file": str(root / "a.env"), "value": "not-the-secret",
         "detector": "generic-high-entropy-string", "confidence": 0.42},
    ]

    result = score(records, findings, root)
    pd = result.per_detector

    # overall still record-counted: 2 positives both caught, 1 FP.
    assert result.overall.tp == 2
    assert result.overall.fp == 1
    assert result.overall.fn == 0

    # aws-access-key: caught r1 (shared) -> tp=1, not unique, no FP.
    assert pd["aws-access-key"].tp == 1
    assert pd["aws-access-key"].unique_tp == 0
    assert pd["aws-access-key"].fp == 0
    assert pd["aws-access-key"].tp_hist[18] == 1  # 0.92 -> bin 18

    # generic detector: caught r1 (shared, tp=1) AND one FP at 0.42 -> bin 8.
    assert pd["generic-high-entropy-string"].tp == 1
    assert pd["generic-high-entropy-string"].unique_tp == 0
    assert pd["generic-high-entropy-string"].fp == 1
    assert pd["generic-high-entropy-string"].fp_hist[8] == 1

    # github-pat: sole catcher of r2 -> unique_tp=1, perfect precision.
    assert pd["github-pat"].tp == 1
    assert pd["github-pat"].unique_tp == 1
    assert pd["github-pat"].fp == 0
    assert round(pd["github-pat"].precision(), 4) == 1.0

    # per-detector FP sums back to the overall FP count.
    assert sum(s.fp for s in pd.values()) == result.overall.fp
