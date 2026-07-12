from bench import leaderboard
from bench.corpora.perf_corpus import KernelCorpus
from bench.scanners.base import RunStats
from bench.schema import ScannerConfig


def test_default_leaderboard_scanners_include_requested_competitors():
    assert {"betterleaks", "kingfisher", "noseyparker", "titus"}.issubset(
        leaderboard._DEFAULT_SCANNERS
    )


def test_leaderboard_run_one_marks_unexpected_exit_as_error(monkeypatch, tmp_path):
    class FakeScanner:
        name = "fake"

        def available(self):
            return True

        def version(self):
            return "fake 1"

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
    # it is marked unavailable — the leaderboard/gate filter on `available`, and
    # ranking a crashed competitor as a real low-recall entrant would be wrong.
    assert result.available is False
    assert result.exit_code == 7
    assert result.error == "scanner exited 7"
