"""Self-test for the attribution rules in score.py.

Runs without keyhog/trufflehog/gitleaks installed by mocking the
scanner adapter directly. Asserts every cell of the TP/FP/FN matrix
matches the SecretBench truth rules.

Invoke as ``python -m pytest tools/secretbench/scoring/test_attribution.py``
or just ``python tools/secretbench/scoring/test_attribution.py``.
"""

from __future__ import annotations

import json
import pathlib
import tempfile

import score


def _make_corpus(tmp: pathlib.Path) -> tuple[list[dict], pathlib.Path]:
    """Build a 4-record corpus on disk:
        - 1 true positive (label=true), secret = "ghp_REALSECRET"
        - 1 true positive (label=true), secret = "AKIAEXAMPLEKEY"
        - 1 negative (label=false), body  = "uuid-4-shape"
        - 1 negative (label=false), body  = "lorem"
    """
    records = []
    for idx, (label, secret, category) in enumerate([
        (True, "ghp_REALSECRET", "authentication-key"),
        (True, "AKIAEXAMPLEKEY", "cloud-service-credential"),
        (False, "11111111-2222-4333-8444-555555555555", "uuid"),
        (False, "lorem ipsum dolor sit amet", "lorem"),
    ]):
        path = tmp / f"f{idx}.env"
        path.write_text(f"KEY={secret}\n")
        rec = {
            "id": f"r{idx}",
            "secret": secret,
            "repo_name": "test/repo",
            "commit_id": "deadbeef" * 5,
            "file_path": str(path),
            "start_line": 1, "end_line": 1,
            "start_column": 4, "end_column": 4 + len(secret),
            "label": label,
            "category": category,
            "comment": "",
            "entropy": 5.0,
            "character_set": "alphanumeric",
            "has_words": False,
            "length": len(secret),
            "is_template": False,
            "is_multiline": False,
            "in_url": False,
            "committer_email": "",
            "commit_date": "",
            "domain": "",
            "file_type": "env",
            "on_disk_path": path.name,
        }
        records.append(rec)
    return records, tmp


def test_perfect_scanner_scores_1_1_0() -> None:
    """A scanner that finds every true positive and never fires on
    a negative gets P=1.0, R=1.0, F1=1.0."""
    with tempfile.TemporaryDirectory() as d:
        tmp = pathlib.Path(d)
        records, root = _make_corpus(tmp)

        def perfect(file_paths):
            findings = []
            for fp in file_paths:
                text = fp.read_text()
                for rec in records:
                    if rec["label"] and rec["secret"] in text and str(fp).endswith(rec["on_disk_path"]):
                        findings.append({
                            "file": str(fp),
                            "line": 1,
                            "value": rec["secret"],
                            "detector": "perfect",
                        })
            return findings

        score.SCANNERS["perfect"] = perfect
        try:
            report = score.score_corpus(records, root, "perfect")
        finally:
            del score.SCANNERS["perfect"]

        assert report.available
        assert report.overall.tp == 2, f"expected tp=2, got {report.overall.tp}"
        assert report.overall.fp == 0, f"expected fp=0, got {report.overall.fp}"
        assert report.overall.fn == 0, f"expected fn=0, got {report.overall.fn}"
        assert report.overall.precision() == 1.0
        assert report.overall.recall() == 1.0
        assert report.overall.f1() == 1.0


def test_noisy_scanner_scores_correctly() -> None:
    """A scanner that fires on EVERY file scores recall=1.0 but
    precision=0.5 (it correctly fired on the 2 TPs and falsely fired
    on the 2 negatives)."""
    with tempfile.TemporaryDirectory() as d:
        tmp = pathlib.Path(d)
        records, root = _make_corpus(tmp)

        def noisy(file_paths):
            findings = []
            for fp in file_paths:
                text = fp.read_text().strip()
                # extract everything after `KEY=`
                value = text.split("=", 1)[1] if "=" in text else text
                findings.append({
                    "file": str(fp),
                    "line": 1,
                    "value": value,
                    "detector": "noisy",
                })
            return findings

        score.SCANNERS["noisy"] = noisy
        try:
            report = score.score_corpus(records, root, "noisy")
        finally:
            del score.SCANNERS["noisy"]

        assert report.available
        assert report.overall.tp == 2
        assert report.overall.fp == 2
        assert report.overall.fn == 0
        assert abs(report.overall.precision() - 0.5) < 1e-9
        assert report.overall.recall() == 1.0


def test_silent_scanner_scores_0_0_2() -> None:
    """A scanner that finds nothing has TP=0, FP=0, FN=2."""
    with tempfile.TemporaryDirectory() as d:
        tmp = pathlib.Path(d)
        records, root = _make_corpus(tmp)

        def silent(file_paths):
            return []

        score.SCANNERS["silent"] = silent
        try:
            report = score.score_corpus(records, root, "silent")
        finally:
            del score.SCANNERS["silent"]

        assert report.overall.tp == 0
        assert report.overall.fp == 0
        assert report.overall.fn == 2
        assert report.overall.precision() == 0.0
        assert report.overall.recall() == 0.0
        assert report.overall.f1() == 0.0


def test_per_category_split() -> None:
    """Per-category counts agree with overall counts (rolled-up sums)."""
    with tempfile.TemporaryDirectory() as d:
        tmp = pathlib.Path(d)
        records, root = _make_corpus(tmp)

        def find_first(file_paths):
            # Only find the first TP (ghp_REALSECRET); miss the AWS one
            for fp in file_paths:
                text = fp.read_text()
                if "ghp_REALSECRET" in text:
                    return [{
                        "file": str(fp),
                        "line": 1,
                        "value": "ghp_REALSECRET",
                        "detector": "first",
                    }]
            return []

        score.SCANNERS["first"] = find_first
        try:
            report = score.score_corpus(records, root, "first")
        finally:
            del score.SCANNERS["first"]

        # 1 TP in authentication-key; 1 FN in cloud-service-credential
        auth = report.per_category["authentication-key"]
        cloud = report.per_category["cloud-service-credential"]
        assert auth.tp == 1 and auth.fp == 0 and auth.fn == 0
        assert cloud.tp == 0 and cloud.fp == 0 and cloud.fn == 1
        # Roll-up matches overall
        assert sum(o.tp for o in report.per_category.values()) == report.overall.tp
        assert sum(o.fn for o in report.per_category.values()) == report.overall.fn


def test_overlap_rule_symmetric() -> None:
    """SecretBench containment rule: one side contains the other.

    Worked examples:
    * `KEY=ghp_X` contains `ghp_X` → TP.
    * `ghp_REALSECRET` contains `REALSECRET` → TP for a scanner
      that surfaces only the high-entropy tail of a prefixed token.
    * `ghp_REALSECRET` equals `ghp_REALSECRET` → TP.

    Counter-example (a known gap, intentional):
    * `ghp_R**` (asterisk-redacted) does NOT contain
      `ghp_REALSECRET` and vice-versa, so a scanner that uses
      character-replacement redaction misses attribution under this
      rule. Both trufflehog and gitleaks default to either NO
      redaction (`--no-verification`) or chunk-truncate redaction
      (`ghp_R…`) so this gap doesn't bite in practice; keyhog
      surfaces full credentials under `--show-secrets`. If a scanner
      that uses char-mask redaction is added we'd need a fuzzier
      `overlap()` (e.g. longest-common-substring threshold).
    """
    assert score.overlap("ghp_X", "KEY=ghp_X")
    assert score.overlap("REALSECRET", "ghp_REALSECRET")
    assert score.overlap("ghp_REALSECRET", "ghp_REALSECRET")
    # Character-replacement redaction is a known gap.
    assert not score.overlap("ghp_R**", "ghp_REALSECRET")
    # No overlap at all → not a TP
    assert not score.overlap("foo", "bar")
    # Empty inputs aren't TPs
    assert not score.overlap("", "ghp_X")
    assert not score.overlap("ghp_X", "")


if __name__ == "__main__":
    test_perfect_scanner_scores_1_1_0()
    test_noisy_scanner_scores_correctly()
    test_silent_scanner_scores_0_0_2()
    test_per_category_split()
    test_overlap_rule_symmetric()
    print("all attribution tests passed")
