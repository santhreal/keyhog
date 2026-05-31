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
