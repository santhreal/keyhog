import json

from bench.corpora.mirror import MirrorCorpus
from bench.corpora.ioc_recovery import IocRecoveryCorpus
from bench.corpora.perf_corpus import KernelCorpus
from bench.runner import build_result, resolve_corpus_with_root, write_result
from bench.scanners.base import RunStats
from bench.schema import ScannerConfig


def test_build_result_scores_and_computes_throughput(tmp_path):
    manifest = tmp_path / "manifest.jsonl"
    manifest.write_text(
        json.dumps(
            {
                "id": "one",
                "secret": "secret-one",
                "label": True,
                "category": "api",
                "on_disk_path": "one.txt",
                "start_line": 1,
                "end_line": 1,
            }
        )
        + "\n",
        encoding="utf-8",
    )
    (tmp_path / "one.txt").write_text("secret-one\n", encoding="utf-8")
    corpus = MirrorCorpus(corpus_dir=tmp_path)

    result = build_result(
        scanner_name="keyhog",
        scanner_version="keyhog 0.test",
        cfg=ScannerConfig(backend="simd", cache="off", daemon="off", mode="full"),
        corpus=corpus,
        findings=[{"file": str(tmp_path / "one.txt"), "line": 1, "value": "secret-one"}],
        stats=RunStats(wall_ms=500.0, peak_rss_kb=1234, exit_code=1),
    )

    assert result.detection.overall.tp == 1
    assert result.detection.overall.fp == 0
    assert result.speed.peak_rss_kb == 1234
    assert result.speed.throughput_mb_s > 0
    assert result.finding_count == 1
    assert result.exit_code == 1
    assert result.timed_out is False


def test_write_result_round_trips_json(tmp_path):
    corpus = KernelCorpus(root=tmp_path)
    result = build_result(
        scanner_name="keyhog",
        scanner_version="keyhog 0.test",
        cfg=ScannerConfig(),
        corpus=corpus,
        findings=[],
        stats=RunStats(),
    )
    output = tmp_path / "result.json"

    write_result(result, output)

    decoded = json.loads(output.read_text(encoding="utf-8"))
    assert decoded["scanner"]["name"] == "keyhog"
    assert decoded["available"] is True


def test_resolve_corpus_with_root_maps_mirror_to_corpus_dir(tmp_path):
    corpus = resolve_corpus_with_root("mirror", tmp_path)

    assert isinstance(corpus, MirrorCorpus)
    assert corpus.root == tmp_path


def test_resolve_corpus_with_root_maps_ioc_recovery_to_corpus_dir(tmp_path):
    corpus = resolve_corpus_with_root("ioc-recovery", tmp_path)

    assert isinstance(corpus, IocRecoveryCorpus)
    assert corpus.root == tmp_path
    assert corpus.scan_root == tmp_path / "corpus"
