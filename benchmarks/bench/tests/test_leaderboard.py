import json

import pytest

from bench import leaderboard
from bench.corpora.perf_corpus import KernelCorpus
from bench.scanners.base import RunStats
from bench.scanners.keyhog import KeyhogScanner
from bench.schema import RunResult, ScannerConfig


def test_default_leaderboard_scanners_include_requested_competitors():
    assert {"betterleaks", "kingfisher", "noseyparker", "titus"}.issubset(
        leaderboard._DEFAULT_SCANNERS
    )


def test_required_matrix_writes_unavailable_row_then_fails(monkeypatch, tmp_path):
    config = ScannerConfig()
    unavailable = RunResult(available=False, error="scanner binary is absent", exit_code=-1)
    unavailable.scanner.name = "fake"
    monkeypatch.setattr(
        leaderboard,
        "_configs_for",
        lambda *args, **kwargs: [config],
    )
    monkeypatch.setattr(
        leaderboard,
        "run_one",
        lambda *args, **kwargs: unavailable,
    )

    with pytest.raises(
        leaderboard.RequiredBenchmarkUnavailable,
        match="fake.*scanner binary is absent",
    ):
        leaderboard.run_leaderboard(
            "mirror",
            ["fake"],
            out_dir=tmp_path,
            verbose=False,
            require_available=True,
        )

    result_path = tmp_path / f"mirror-fake-{config.config_id}.json"
    payload = json.loads(result_path.read_text(encoding="utf-8"))
    assert payload["available"] is False
    assert payload["exit_code"] == -1


def test_perf_tier_uses_only_corpus_eligible_default_axes(monkeypatch):
    scanner = KeyhogScanner(binary="/unused/keyhog")
    monkeypatch.setattr(leaderboard, "resolve_scanner", lambda *args, **kw: scanner)

    tree = leaderboard._configs_for("keyhog", "perf", None, "kernel")
    daemon_file = leaderboard._configs_for("keyhog", "perf", None, "daemon-file")

    assert {cfg.daemon for cfg in tree} == {"off"}
    assert {cfg.cache for cfg in tree} == {"off", "on"}
    assert {cfg.mode for cfg in tree} == {"full", "fast", "deep", "precision"}
    assert {cfg.daemon for cfg in daemon_file} == {"off", "on"}
    assert {cfg.cache for cfg in daemon_file} == {"off"}
    assert {cfg.mode for cfg in daemon_file} == {"full"}
    assert not any(
        cfg.backend == "auto" and cfg.daemon == "on" for cfg in daemon_file
    )


def test_leaderboard_run_one_marks_unexpected_exit_as_error(monkeypatch, tmp_path):
    class FakeScanner:
        name = "fake"

        def available(self):
            return True

        def version(self):
            return "fake 1"

        def detector_corpus_sha256(self):
            return "c" * 64

        def default_config(self):
            return ScannerConfig()

        def exit_success(self, code):
            return code == 0

        def run(self, root, cfg, output=None):
            return [], RunStats(exit_code=7, wall_ms=1.0)

    monkeypatch.setattr(leaderboard, "resolve_scanner", lambda *args, **kw: FakeScanner())
    monkeypatch.setattr(
        leaderboard,
        "resolve_corpus_with_root",
        lambda *args, **kw: KernelCorpus(root=tmp_path),
    )

    result = leaderboard.run_one("fake", "kernel", ScannerConfig(), corpus_root=tmp_path)

    # A crashed scanner (nonzero, non-success exit) produced no usable result, so
    # it is marked unavailable, the leaderboard/gate filter on `available`, and
    # ranking a crashed competitor as a real low-recall entrant would be wrong.
    assert result.available is False
    assert result.exit_code == 7
    assert result.error == "scanner exited 7"
    assert result.scanner.detector_corpus_sha256 == "c" * 64
