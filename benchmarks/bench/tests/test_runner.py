import json

from bench import runner
from bench.corpora.mirror import MirrorCorpus
from bench.corpora.ioc_recovery import IocRecoveryCorpus
from bench.corpora.perf_corpus import KernelCorpus
from bench.runner import build_result, resolve_corpus_with_root, write_result
from bench.scanners.base import MeasurementProvenance, RunStats
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
        executable_sha256="a" * 64,
        detector_corpus_sha256="b" * 64,
    )

    assert result.detection.overall.tp == 1
    assert result.detection.overall.fp == 0
    assert result.speed.peak_rss_kb == 1234
    assert result.speed.throughput_mb_s > 0
    assert result.finding_count == 1
    assert result.exit_code == 1
    assert result.timed_out is False
    assert result.scanner.executable_sha256 == "a" * 64
    assert result.scanner.detector_corpus_sha256 == "b" * 64


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


def test_runner_rejects_daemon_scoring_on_labeled_corpus(tmp_path):
    (tmp_path / "manifest.jsonl").write_text(
        json.dumps(
            {
                "id": "one",
                "secret": "secret-one",
                "label": True,
                "category": "api",
                "on_disk_path": "one.txt",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    (tmp_path / "one.txt").write_text("secret-one\n", encoding="utf-8")

    class FakeScanner:
        name = "keyhog"

    result = runner._run_resolved_scanner(
        FakeScanner(),
        "keyhog test",
        ScannerConfig(backend="simd", daemon="on"),
        MirrorCorpus(corpus_dir=tmp_path),
    )

    assert result.available is False
    assert result.exit_code == -1
    assert "production daemon CLI forbids plaintext" in result.error


def test_run_once_rejects_detector_corpus_mutation(monkeypatch, tmp_path):
    digests = iter(["a" * 64, "b" * 64])

    class FakeScanner:
        name = "keyhog"

        def version(self):
            return "keyhog 0.test"

        def detector_corpus_sha256(self):
            return next(digests)

        def available(self):
            return True

        def default_config(self):
            return ScannerConfig()

        def run(self, root, cfg, output=None, timeout=3600):
            return [], RunStats(exit_code=0)

        def exit_success(self, code):
            return code == 0

    monkeypatch.setattr(runner, "resolve_scanner", lambda *args, **kwargs: FakeScanner())
    monkeypatch.setattr(
        runner, "resolve_corpus_with_root",
        lambda *args, **kwargs: KernelCorpus(root=tmp_path),
    )

    result = runner.run_once(scanner_name="keyhog", corpus_name="kernel")

    assert result.available is False
    assert result.scanner.detector_corpus_sha256 == "a" * 64
    assert result.error == (
        "detector corpus changed during the measured scan; "
        "rerun against stable detector bytes"
    )


def test_run_once_uses_adapter_provenance_bound_scan(monkeypatch, tmp_path):
    class FakeScanner:
        name = "keyhog"

        def version(self):
            return "keyhog 0.test"

        def detector_corpus_sha256(self):
            return "a" * 64

        def available(self):
            return True

        def default_config(self):
            return ScannerConfig()

        def run(self, root, cfg, output=None, timeout=3600):
            raise AssertionError("unbound scan path must not run")

        def run_with_provenance(self, root, cfg):
            return [], RunStats(exit_code=0), MeasurementProvenance(
                scanner_version="KeyHog snapshot",
                executable_sha256="b" * 64,
                detector_corpus_sha256="c" * 64,
                execution_route="in_process",
            )

        def exit_success(self, code):
            return code == 0

    monkeypatch.setattr(runner, "resolve_scanner", lambda *args, **kwargs: FakeScanner())
    monkeypatch.setattr(
        runner, "resolve_corpus_with_root",
        lambda *args, **kwargs: KernelCorpus(root=tmp_path),
    )

    result = runner.run_once(scanner_name="keyhog", corpus_name="kernel")

    assert result.available is True
    assert result.scanner.version == "KeyHog snapshot"
    assert result.scanner.executable_sha256 == "b" * 64
    assert result.scanner.detector_corpus_sha256 == "c" * 64


def test_run_once_reports_post_scan_provenance_failure(monkeypatch, tmp_path):
    calls = 0

    class FakeScanner:
        name = "keyhog"

        def version(self):
            return "keyhog 0.test"

        def detector_corpus_sha256(self):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError("detector storage disappeared")
            return "a" * 64

        def available(self):
            return True

        def default_config(self):
            return ScannerConfig()

        def run(self, root, cfg, output=None, timeout=3600):
            return [], RunStats(exit_code=0)

        def exit_success(self, code):
            return code == 0

    monkeypatch.setattr(runner, "resolve_scanner", lambda *args, **kwargs: FakeScanner())
    monkeypatch.setattr(
        runner, "resolve_corpus_with_root",
        lambda *args, **kwargs: KernelCorpus(root=tmp_path),
    )

    result = runner.run_once(scanner_name="keyhog", corpus_name="kernel")

    assert result.available is False
    assert result.error == (
        "detector provenance failed after scan: "
        "OSError: detector storage disappeared"
    )


def test_run_once_snapshot_provenance_does_not_reprobe_mutable_workspace(
    monkeypatch, tmp_path
):
    freshness_checks = 0

    class FakeScanner:
        name = "keyhog"

        def version(self):
            return "keyhog 0.test"

        def assert_freshness(self):
            nonlocal freshness_checks
            freshness_checks += 1
            if freshness_checks == 2:
                raise RuntimeError("tracked workspace changed")

        def detector_corpus_sha256(self):
            return "a" * 64

        def available(self):
            return True

        def default_config(self):
            return ScannerConfig()

        def run_with_provenance(self, root, cfg):
            return [], RunStats(exit_code=0), MeasurementProvenance(
                scanner_version="KeyHog snapshot",
                executable_sha256="b" * 64,
                detector_corpus_sha256="a" * 64,
                execution_route="in_process",
            )

        def exit_success(self, code):
            return code == 0

    monkeypatch.setattr(runner, "resolve_scanner", lambda *args, **kwargs: FakeScanner())
    monkeypatch.setattr(
        runner, "resolve_corpus_with_root",
        lambda *args, **kwargs: KernelCorpus(root=tmp_path),
    )

    result = runner.run_once(scanner_name="keyhog", corpus_name="kernel")

    assert result.available is True
    assert freshness_checks == 1
    assert result.scanner.version == "KeyHog snapshot"


def test_run_once_records_snapshot_when_source_binary_changes(monkeypatch, tmp_path):
    identities = iter(["KeyHog identity A", "KeyHog identity B"])

    class FakeScanner:
        name = "keyhog"

        def version(self):
            return "untrusted early probe"

        def assert_freshness(self):
            return next(identities)

        def detector_corpus_sha256(self):
            return "a" * 64

        def available(self):
            return True

        def default_config(self):
            return ScannerConfig()

        def run_with_provenance(self, root, cfg):
            return [], RunStats(exit_code=0), MeasurementProvenance(
                scanner_version="KeyHog snapshot A",
                executable_sha256="b" * 64,
                detector_corpus_sha256="a" * 64,
                execution_route="in_process",
            )

        def exit_success(self, code):
            return code == 0

    monkeypatch.setattr(runner, "resolve_scanner", lambda *args, **kwargs: FakeScanner())
    monkeypatch.setattr(
        runner, "resolve_corpus_with_root",
        lambda *args, **kwargs: KernelCorpus(root=tmp_path),
    )

    result = runner.run_once(scanner_name="keyhog", corpus_name="kernel")

    assert result.available is True
    assert result.scanner.version == "KeyHog snapshot A"
    assert result.scanner.executable_sha256 == "b" * 64
