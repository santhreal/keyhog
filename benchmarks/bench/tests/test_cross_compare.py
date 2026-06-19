import json
import pathlib

from bench import cross_compare
from bench.schema import CorpusInfo, Detection, Host, Outcome, RunResult, Speed
from bench.schema import Scanner as ScannerRecord
from bench.schema import ScannerConfig


def _write(
    dev_dir: pathlib.Path,
    scanner: str,
    tp: int,
    fp: int,
    fn: int,
    os_: str,
    speed: float = 0.0,
):
    dev_dir.mkdir(parents=True, exist_ok=True)
    r = RunResult(
        scanner=ScannerRecord(name=scanner, version="t", config=ScannerConfig()),
        corpus=CorpusInfo(name="mirror", fixture_count=10, labeled_positives=tp + fn),
        detection=Detection(overall=Outcome(tp=tp, fp=fp, fn=fn)),
        host=Host(os=os_, cpu="cpu"),
        speed=Speed(throughput_mb_s=speed),
        finding_count=tp + fp,
    )
    (dev_dir / f"mirror-{scanner}.json").write_text(json.dumps(r.to_json()))


def test_rows_collected_per_device_and_sorted_by_f1(tmp_path: pathlib.Path):
    _write(tmp_path / "linux", "keyhog", tp=9, fp=1, fn=1, os_="Linux")    # F1≈0.90
    _write(tmp_path / "mac", "keyhog", tp=8, fp=2, fn=2, os_="Darwin")     # F1=0.80
    rows = cross_compare.rows_for(tmp_path, "mirror", "keyhog")
    assert {d for d, _ in rows} == {"linux", "mac"}
    table = cross_compare.render(rows)
    # Higher-F1 host (linux) renders above the lower-F1 host (mac).
    assert table.index("linux") < table.index("mac")
    assert "Linux" in table and "Darwin" in table


def test_scanner_filter_and_corpus_filter(tmp_path: pathlib.Path):
    _write(tmp_path / "linux", "keyhog", tp=9, fp=1, fn=1, os_="Linux")
    _write(tmp_path / "linux", "trufflehog", tp=3, fp=0, fn=7, os_="Linux")
    only_kh = cross_compare.rows_for(tmp_path, "mirror", "keyhog")
    assert [r.scanner.name for _, r in only_kh] == ["keyhog"]
    # Wrong corpus name -> nothing.
    assert cross_compare.rows_for(tmp_path, "creddata", None) == []


def test_empty_root_is_graceful(tmp_path: pathlib.Path):
    assert cross_compare.rows_for(tmp_path / "nope", "mirror", None) == []
    assert "No cross-device" in cross_compare.render([])


def test_dominance_gate_fails_when_required_os_or_competitor_missing(tmp_path: pathlib.Path):
    _write(tmp_path / "linux", "keyhog", tp=10, fp=0, fn=0, os_="Linux", speed=1000)
    _write(tmp_path / "linux", "betterleaks", tp=8, fp=0, fn=2, os_="Linux", speed=20)
    verdict = cross_compare.evaluate_dominance(
        cross_compare.rows_for(tmp_path, "mirror", None),
        required_oses=("linux", "macos"),
    )
    assert not verdict.ok
    assert "missing required competitor result: kingfisher" in verdict.violations
    assert "missing required keyhog OS result: macos" in verdict.violations


def test_dominance_gate_uses_competitor_fastest_path_across_devices(tmp_path: pathlib.Path):
    _write(tmp_path / "linux", "keyhog", tp=10, fp=0, fn=0, os_="Linux", speed=900)
    _write(tmp_path / "mac", "keyhog", tp=10, fp=0, fn=0, os_="Darwin", speed=1200)
    _write(tmp_path / "win", "keyhog", tp=10, fp=0, fn=0, os_="Windows", speed=1000)
    _write(tmp_path / "linux", "betterleaks", tp=8, fp=0, fn=2, os_="Linux", speed=10)
    _write(tmp_path / "mac", "betterleaks", tp=8, fp=0, fn=2, os_="Darwin", speed=95)
    _write(tmp_path / "linux", "kingfisher", tp=7, fp=0, fn=3, os_="Linux", speed=40)
    verdict = cross_compare.evaluate_dominance(
        cross_compare.rows_for(tmp_path, "mirror", None),
        required_oses=("linux", "macos", "windows"),
    )
    assert not verdict.ok
    assert verdict.competitor_best["betterleaks"] == 95
    assert any("linux: keyhog 900.0000 MB/s < 10.0x betterleaks" in v for v in verdict.violations)
    assert not any("macos: keyhog" in v for v in verdict.violations)


def test_dominance_gate_fails_accuracy_regression_even_when_fast_enough(tmp_path: pathlib.Path):
    _write(tmp_path / "linux", "keyhog", tp=7, fp=0, fn=3, os_="Linux", speed=1000)
    _write(tmp_path / "better", "betterleaks", tp=10, fp=0, fn=0, os_="Linux", speed=1)
    _write(tmp_path / "king", "kingfisher", tp=6, fp=0, fn=4, os_="Linux", speed=1)
    verdict = cross_compare.evaluate_dominance(
        cross_compare.rows_for(tmp_path, "mirror", None),
        required_oses=("linux",),
    )
    assert not verdict.ok
    assert any("keyhog recall 0.7000 < betterleaks recall 1.0000" in v for v in verdict.violations)
