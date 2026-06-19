import json

import pytest

from bench import report
from bench.schema import CorpusInfo, Detection, Outcome, RunResult
from bench.schema import Scanner as ScannerRecord
from bench.schema import ScannerConfig, Speed


def _result(scanner: str, hits: int, wall_ms: float) -> RunResult:
    return RunResult(
        scanner=ScannerRecord(name=scanner, version="test", config=ScannerConfig()),
        corpus=CorpusInfo(name="mirror", fixture_count=10, labeled_positives=5, bytes=100),
        detection=Detection(overall=Outcome(tp=hits, fp=0, fn=5 - hits)),
        speed=Speed(wall_ms=wall_ms, throughput_mb_s=1.0, peak_rss_kb=1024),
        finding_count=hits,
    )


def test_report_renders_keyhog_leaderboard_row():
    text = report.render_leaderboard(
        [_result("betterleaks", 2, 10.0), _result("keyhog", 5, 20.0)],
        "mirror",
    )

    assert "**KeyHog**" in text
    assert "BetterLeaks" in text
    assert "Corpus: **mirror**" in text


def test_report_inject_replaces_marker_body():
    original = "a\n<!-- BENCH:perf:start -->\nold\n<!-- BENCH:perf:end -->\nz"

    updated = report.inject(original, "perf", "new")

    assert updated == "a\n<!-- BENCH:perf:start -->\nnew\n<!-- BENCH:perf:end -->\nz"


def test_report_check_does_not_write_stale_reports(tmp_path, capsys):
    result = _result("keyhog", 5, 20.0)
    results_dir = tmp_path / "results"
    reports_dir = tmp_path / "reports"
    readme = tmp_path / "README.md"
    results_dir.mkdir()
    (results_dir / "run.json").write_text(json.dumps(result.to_json()), encoding="utf-8")

    text = "\n".join([
        "<!-- BENCH:leaderboard:start -->",
        "old",
        "<!-- BENCH:leaderboard:end -->",
        "<!-- BENCH:perf:start -->",
        "old",
        "<!-- BENCH:perf:end -->",
        "<!-- BENCH:gaps:start -->",
        "old",
        "<!-- BENCH:gaps:end -->",
        "",
    ])
    sections = report.build_sections([result], "mirror")
    for name, body in sections.items():
        text = report.inject(text, name, body)
    readme.write_text(text, encoding="utf-8")

    code = report._main([
        "--results",
        str(results_dir),
        "--reports",
        str(reports_dir),
        "--readme",
        str(readme),
        "--corpus",
        "mirror",
        "--check",
    ])

    assert code == 1
    assert not reports_dir.exists()
    assert "Benchmark reports are stale" in capsys.readouterr().err


def test_gap_report_shows_category_recall_gap_dashboard():
    keyhog = _result("keyhog", 3, 20.0)
    keyhog.detection.per_category = {"generic": Outcome(tp=1, fp=0, fn=2)}
    noisy = _result("betterleaks", 2, 10.0)
    noisy.detection.overall = Outcome(tp=2, fp=8, fn=3)
    noisy.detection.per_category = {"generic": Outcome(tp=3, fp=1, fn=0)}

    text = report.render_gaps([keyhog, noisy], "mirror")

    assert "KeyHog P/R/F1" in text
    assert "Recall gap" in text
    assert "| `generic` | 1.000 / 0.333 / 0.500 | 1/2 | BetterLeaks 0.750 / 1.000 / 0.857 | +0.667 |" in text


def test_class_recall_differential_requires_full_scanner_set():
    keyhog = _result("keyhog", 3, 20.0)
    keyhog.detection.per_category = {"generic": Outcome(tp=1, fp=0, fn=2)}
    better = _result("betterleaks", 2, 10.0)
    better.detection.per_category = {"generic": Outcome(tp=3, fp=1, fn=0)}

    with pytest.raises(ValueError, match="missing required scanner"):
        report.class_recall_differential(
            [keyhog, better],
            "mirror",
            report.FULL_DIFFERENTIAL_SCANNERS,
        )


def test_class_recall_differential_records_competitor_map():
    rows = []
    for name, tp in [
        ("keyhog", 1),
        ("betterleaks", 3),
        ("kingfisher", 2),
        ("trufflehog", 1),
        ("titus", 1),
        ("noseyparker", 0),
    ]:
        result = _result(name, tp, 10.0)
        result.detection.per_category = {"generic": Outcome(tp=tp, fp=0, fn=3 - tp)}
        rows.append(result)

    diff = report.class_recall_differential(
        rows,
        "mirror",
        report.FULL_DIFFERENTIAL_SCANNERS,
    )

    generic = diff["rows"]["generic"]
    assert diff["scanner_count"] == 6
    assert set(generic["competitors"]) == {
        "betterleaks",
        "kingfisher",
        "trufflehog",
        "titus",
        "noseyparker",
    }
    assert generic["best_competitor"]["scanner"] == "betterleaks"
    assert generic["recall_gap"] == 0.6667
