import hashlib
import json
import pytest

from bench import runner
from bench.corpora.mirror import MirrorCorpus
from bench.corpora.ioc_recovery import IocRecoveryCorpus
from bench.corpora.perf_corpus import KernelCorpus
from bench.runner import build_result, resolve_corpus_with_root, write_result
from bench.scanners.base import MeasurementProvenance, RunStats
from bench.hosted_cpu_gate import CONTEXT_SCHEMA
from bench.schema import ScannerConfig, StaticRecoveryMetrics


def _static_recovery_json(
    *, supported: int = 0, unsupported: int = 0, erroneous: int = 0,
    reasons: dict[str, int] | None = None,
) -> dict:
    return StaticRecoveryMetrics(
        supported=supported,
        unsupported=unsupported,
        erroneous=erroneous,
        reasons=reasons or {},
    ).to_json()


def test_build_result_scores_and_computes_throughput(tmp_path):
    """Guards build result scores and computes throughput; prevents this evidence regression from false-passing or crashing."""
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
        static_recovery=StaticRecoveryMetrics(
            supported=2,
            unsupported=1,
            erroneous=1,
            reasons={"unsupported_call": 1, "json_utf8": 1},
        ),
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
    assert result.static_recovery == StaticRecoveryMetrics(
        supported=2,
        unsupported=1,
        erroneous=1,
        reasons={"unsupported_call": 1, "json_utf8": 1},
    )


def test_write_result_round_trips_json(tmp_path):
    """Guards write result round trips json; prevents this evidence regression from false-passing or crashing."""
    corpus = KernelCorpus(root=tmp_path)
    result = build_result(
        scanner_name="keyhog",
        scanner_version="keyhog 0.test",
        cfg=ScannerConfig(),
        corpus=corpus,
        findings=[],
        stats=RunStats(),
        static_recovery=StaticRecoveryMetrics(),
    )
    output = tmp_path / "result.json"

    write_result(result, output)

    decoded = json.loads(output.read_text(encoding="utf-8"))
    assert decoded["scanner"]["name"] == "keyhog"
    assert decoded["available"] is True


def test_runner_hashes_competitor_executable_identity(tmp_path):
    """Guards runner hashes competitor executable identity; prevents this evidence regression from false-passing or crashing."""
    binary = tmp_path / "competitor"
    payload = b"immutable competitor build\n"
    binary.write_bytes(payload)

    scanner = type("Scanner", (), {"binary": str(binary)})()
    digest = runner._scanner_executable_sha256(scanner)

    assert digest == hashlib.sha256(payload).hexdigest()


def test_runner_persists_competitor_executable_identity(tmp_path, monkeypatch):
    """Guards runner persists competitor executable identity; prevents this evidence regression from false-passing or crashing."""
    binary = tmp_path / "competitor"
    payload = b"competitor build used by the measured row\n"
    binary.write_bytes(payload)

    class FakeScanner:
        name = "betterleaks"
        binary = ""

        def version(self):
            return "betterleaks 1.test"

        def available(self):
            return True

        def detector_corpus_sha256(self):
            return ""

        def default_config(self):
            return ScannerConfig()

        def run(self, root, cfg, output=None, timeout=3600):
            return [], RunStats(exit_code=0)

        def exit_success(self, code):
            return code == 0

    FakeScanner.binary = str(binary)
    monkeypatch.setattr(runner, "resolve_scanner", lambda *args, **kwargs: FakeScanner())
    monkeypatch.setattr(
        runner,
        "resolve_corpus_with_root",
        lambda *args, **kwargs: KernelCorpus(root=tmp_path),
    )

    result = runner.run_once(scanner_name="betterleaks", corpus_name="kernel")

    assert result.available is True
    assert result.scanner.executable_sha256 == hashlib.sha256(payload).hexdigest()


def test_resolve_corpus_with_root_maps_mirror_to_corpus_dir(tmp_path):
    """Guards resolve corpus with root maps mirror to corpus dir; prevents this evidence regression from false-passing or crashing."""
    corpus = resolve_corpus_with_root("mirror", tmp_path)

    assert isinstance(corpus, MirrorCorpus)
    assert corpus.root == tmp_path


def test_resolve_corpus_with_root_maps_ioc_recovery_to_corpus_dir(tmp_path):
    """Guards resolve corpus with root maps ioc recovery to corpus dir; prevents this evidence regression from false-passing or crashing."""
    corpus = resolve_corpus_with_root("ioc-recovery", tmp_path)

    assert isinstance(corpus, IocRecoveryCorpus)
    assert corpus.root == tmp_path
    assert corpus.scan_root == tmp_path / "corpus"


def test_runner_rejects_daemon_scoring_on_labeled_corpus(tmp_path):
    """Guards runner rejects daemon scoring on labeled corpus; prevents this evidence regression from false-passing or crashing."""
    (tmp_path / "manifest.jsonl").write_text(
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
    """Guards run once rejects detector corpus mutation; prevents this evidence regression from false-passing or crashing."""
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
    """Guards run once uses adapter provenance bound scan; prevents this evidence regression from false-passing or crashing."""
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
                static_recovery=_static_recovery_json(supported=3),
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
    """Guards run once reports post scan provenance failure; prevents this evidence regression from false-passing or crashing."""
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
    """Guards run once snapshot provenance does not reprobe mutable workspace; prevents this evidence regression from false-passing or crashing."""
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
                static_recovery=_static_recovery_json(),
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
    """Guards run once records snapshot when source binary changes; prevents this evidence regression from false-passing or crashing."""
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
                static_recovery=_static_recovery_json(),
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

def _bloom_receipt() -> dict[str, object]:
    return {
        "schema_version": "bloom-evidence-v1",
        "corpus_name": "creddata-test",
        "corpus_revision": "f1de3f85dbdf42bf7b3467c0d273a4dfe44d56ee",
        "fixture_sha256": "1" * 64,
        "corpus_sha256": "2" * 64,
        "detector_corpus_sha256": "3" * 64,
        "scanner_detector_digest": "4" * 16,
        "executable_sha256": "6" * 64,
        "workspace_detector_corpus_sha256": "7" * 64,
        "declared_input_count": 12,
        "unavailable_input_count": 2,
        "unavailable_reason_counts": {"source-file-missing": 2},
        "input_count": 10,
        "eligible_input_count": 8,
        "admitted_input_count": 6,
        "rejected_input_count": 4,
        "rejection_basis_points": 4_000,
        "populated_slots": 18_437,
        "total_slots": 65_536,
        "saturation_threshold_slots": 39_322,
        "density_basis_points": 2_813,
        "state": "healthy",
        "enabled_finding_count": 7,
        "bypass_finding_count": 7,
        "enabled_findings_sha256": "5" * 64,
        "bypass_findings_sha256": "5" * 64,
        "findings_identical": True,
    }


def test_bloom_linkage_keeps_semantic_and_raw_detector_digests_separate(
    tmp_path, monkeypatch
):
    """Guards bloom linkage keeps semantic and raw detector digests separate; prevents this evidence regression from false-passing or crashing."""
    receipt = tmp_path / "bloom.json"
    receipt.write_text(json.dumps(_bloom_receipt()), encoding="utf-8")
    monkeypatch.setenv("KEYHOG_BENCH_BLOOM_RESULT", str(receipt))

    evidence = runner._load_bloom_evidence("keyhog", "7" * 64, "6" * 64)

    assert evidence.detector_corpus_sha256 == "3" * 64
    assert evidence.scanner_detector_digest == "4" * 16
    assert evidence.workspace_detector_corpus_sha256 == "7" * 64
    assert evidence.executable_sha256 == "6" * 64


@pytest.mark.parametrize(
    ("workspace_digest", "executable_digest", "message"),
    [
        ("8" * 64, "6" * 64, "workspace detector corpus SHA-256"),
        ("7" * 64, "8" * 64, "executable SHA-256"),
    ],
)
def test_bloom_linkage_rejects_wrong_owner_identity(
    tmp_path,
    monkeypatch,
    workspace_digest,
    executable_digest,
    message,
):
    """Guards bloom linkage rejects wrong owner identity; prevents this evidence regression from false-passing or crashing."""
    receipt = tmp_path / "bloom.json"
    receipt.write_text(json.dumps(_bloom_receipt()), encoding="utf-8")
    monkeypatch.setenv("KEYHOG_BENCH_BLOOM_RESULT", str(receipt))

    with pytest.raises(ValueError, match=message):
        runner._load_bloom_evidence(
            "keyhog",
            workspace_digest,
            executable_digest,
        )

def _hosted_context() -> dict[str, object]:
    return {
        "schema_version": CONTEXT_SCHEMA,
        "runner": {
            "repository": "owner/keyhog",
            "workflow_ref": "owner/keyhog/.github/workflows/bench.yml@refs/heads/main",
            "workflow_sha": "a" * 40,
            "run_id": "987654",
            "run_attempt": "3",
            "job": "leaderboard",
        },
    }


class _HostedFakeScanner:
    name = "betterleaks"
    binary = ""

    def available(self):
        return True

    def detector_corpus_sha256(self):
        return ""

    def run(self, root, cfg, output=None, timeout=3600):
        return [], RunStats(exit_code=0)

    def exit_success(self, code):
        return code == 0


def test_runner_binds_context_digest_and_run_identity(tmp_path, monkeypatch):
    """Guards runner binds context digest and run identity; prevents this evidence regression from false-passing or crashing."""
    context = tmp_path / "hosted-context.json"
    raw = json.dumps(_hosted_context(), sort_keys=True).encode("utf-8") + b"\n"
    context.write_bytes(raw)
    (tmp_path / "input.txt").write_text("stable workload\n", encoding="utf-8")
    monkeypatch.setenv("KEYHOG_BENCH_HOSTED_CONTEXT", str(context))

    result = runner._run_resolved_scanner(
        _HostedFakeScanner(),
        "betterleaks test",
        ScannerConfig(),
        KernelCorpus(root=tmp_path),
    )

    assert result.available is True
    assert result.hosted_binding is not None
    assert result.hosted_binding.context_sha256 == hashlib.sha256(raw).hexdigest()
    assert result.hosted_binding.repository == "owner/keyhog"
    assert result.hosted_binding.workflow_sha == "a" * 40
    assert result.hosted_binding.run_id == "987654"
    assert result.hosted_binding.run_attempt == "3"
    assert result.hosted_binding.job == "leaderboard"


def test_runner_attaches_binding_to_unavailable_result(tmp_path, monkeypatch):
    """Guards runner attaches binding to unavailable result; prevents this evidence regression from false-passing or crashing."""
    context = tmp_path / "hosted-context.json"
    context.write_text(json.dumps(_hosted_context()), encoding="utf-8")
    monkeypatch.setenv("KEYHOG_BENCH_HOSTED_CONTEXT", str(context))
    scanner = _HostedFakeScanner()
    monkeypatch.setattr(scanner, "available", lambda: False)

    result = runner._run_resolved_scanner(
        scanner,
        "betterleaks test",
        ScannerConfig(),
        KernelCorpus(root=tmp_path),
    )

    assert result.available is False
    assert result.hosted_binding is not None
    assert result.hosted_binding.run_id == "987654"


def test_runner_rejects_obsolete_v1_hosted_context(tmp_path, monkeypatch):
    """An obsolete v1 context cannot bind a benchmark result after the v2 cutover."""
    value = _hosted_context()
    value["schema_version"] = "hosted-cpu-context-v1"
    context = tmp_path / "hosted-context.json"
    context.write_text(json.dumps(value), encoding="utf-8")
    monkeypatch.setenv("KEYHOG_BENCH_HOSTED_CONTEXT", str(context))

    result = runner._run_resolved_scanner(
        _HostedFakeScanner(),
        "betterleaks test",
        ScannerConfig(),
        KernelCorpus(root=tmp_path),
    )

    assert result.available is False
    assert result.hosted_binding is None
    assert (
        f"hosted context schema_version must be {CONTEXT_SCHEMA!r}"
        in result.error
    )


def test_runner_rejects_malformed_hosted_context_binding(tmp_path, monkeypatch):
    """Guards runner rejects malformed hosted context binding; prevents this evidence regression from false-passing or crashing."""
    value = _hosted_context()
    value["runner"]["run_attempt"] = True
    context = tmp_path / "hosted-context.json"
    context.write_text(json.dumps(value), encoding="utf-8")
    monkeypatch.setenv("KEYHOG_BENCH_HOSTED_CONTEXT", str(context))

    result = runner._run_resolved_scanner(
        _HostedFakeScanner(),
        "betterleaks test",
        ScannerConfig(),
        KernelCorpus(root=tmp_path),
    )

    assert result.available is False
    assert result.hosted_binding is None
    assert "hosted context failed" in result.error
    assert "run_attempt must be a non-empty string" in result.error


def test_corpus_mutation_during_scanner_run_becomes_unavailable(
    tmp_path, monkeypatch
):
    """Guards corpus mutation during scanner run becomes unavailable; prevents this evidence regression from false-passing or crashing."""
    monkeypatch.delenv("KEYHOG_BENCH_HOSTED_CONTEXT", raising=False)
    target = tmp_path / "input.txt"
    target.write_text("before\n", encoding="utf-8")

    class MutatingScanner(_HostedFakeScanner):
        def run(self, root, cfg, output=None, timeout=3600):
            target.write_text("after\n", encoding="utf-8")
            return [], RunStats(exit_code=0)

    result = runner._run_resolved_scanner(
        MutatingScanner(),
        "betterleaks test",
        ScannerConfig(),
        KernelCorpus(root=tmp_path),
    )

    assert result.available is False
    assert result.exit_code == -1
    assert result.error.startswith("workload changed during scan: RuntimeError:")
