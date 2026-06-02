import json
import pathlib

from bench import cross_compare
from bench.schema import CorpusInfo, Detection, Host, Outcome, RunResult
from bench.schema import Scanner as ScannerRecord
from bench.schema import ScannerConfig


def _write(dev_dir: pathlib.Path, scanner: str, tp: int, fp: int, fn: int, os_: str):
    dev_dir.mkdir(parents=True, exist_ok=True)
    r = RunResult(
        scanner=ScannerRecord(name=scanner, version="t", config=ScannerConfig()),
        corpus=CorpusInfo(name="mirror", fixture_count=10, labeled_positives=tp + fn),
        detection=Detection(overall=Outcome(tp=tp, fp=fp, fn=fn)),
        host=Host(os=os_, cpu="cpu"),
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
