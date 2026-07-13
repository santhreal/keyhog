"""Executable product target for deterministic P0-P12 secret recovery."""

from __future__ import annotations

import pytest

from bench.corpora.ioc_recovery import IocRecoveryCorpus
from bench.keyhog_version import assert_keyhog_binary_current
from bench.scanners.keyhog import KeyhogScanner, resolve_keyhog_binary
from bench.schema import Detection, Outcome, ScannerConfig
from bench.score import score

pytestmark = pytest.mark.target_spec


@pytest.fixture(scope="session")
def deep_recovery_detection() -> Detection:
    corpus = IocRecoveryCorpus()
    if not corpus.manifest.is_file():
        pytest.fail(
            "IoC-recovery corpus is absent; run "
            "`make -C benchmarks ioc-recovery-corpus`"
        )
    binary = resolve_keyhog_binary()
    if binary is None:
        pytest.fail("current KeyHog release binary is absent; build it before scoring")
    assert_keyhog_binary_current(binary)
    scanner = KeyhogScanner(binary=binary)
    config = ScannerConfig(
        backend="simd",
        cache="off",
        daemon="off",
        mode="deep",
    )
    findings, stats = scanner.run(corpus.scan_root, config)
    assert scanner.exit_success(stats.exit_code), (
        f"deep recovery scan exited {stats.exit_code}, so no score is trustworthy"
    )
    return score(corpus.records(), findings, corpus.file_root)


def test_deep_mode_recovers_every_plaintext_exactly(
    deep_recovery_detection: Detection,
):
    outcome = deep_recovery_detection.overall
    assert (outcome.tp, outcome.fp, outcome.fn) == (4_368, 0, 0), (
        "deep recovery target requires exact recovery without extra findings "
        f"across all P0-P12 fixtures; got TP={outcome.tp}, "
        f"FP={outcome.fp}, FN={outcome.fn}"
    )


def test_deep_mode_has_no_blind_recovery_phase(
    deep_recovery_detection: Detection,
):
    assert len(deep_recovery_detection.per_category) == 13
    failures = {
        category: (outcome.tp, outcome.fp, outcome.fn)
        for category, outcome in deep_recovery_detection.per_category.items()
        if (outcome.tp, outcome.fp, outcome.fn) != (336, 0, 0)
    }
    assert not failures, f"deep recovery phase gaps: {failures}"


def test_deep_recovery_target_rejects_one_extra_finding():
    detection = Detection(
        overall=Outcome(tp=4_368, fp=1, fn=0),
        per_category={
            f"P{phase}": Outcome(tp=336, fp=int(phase == 7), fn=0)
            for phase in range(13)
        },
    )

    with pytest.raises(AssertionError, match=r"FP=1"):
        test_deep_mode_recovers_every_plaintext_exactly(detection)
    with pytest.raises(AssertionError, match=r"P7.*336, 1, 0"):
        test_deep_mode_has_no_blind_recovery_phase(detection)
