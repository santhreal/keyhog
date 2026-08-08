"""Executable product target for bounded static secret recovery."""

from __future__ import annotations

from collections import Counter

import pytest

from bench.corpora.ioc_recovery import IocRecoveryCorpus
from bench.keyhog_version import assert_keyhog_binary_current
from bench.scanners.keyhog import KeyhogScanner, resolve_keyhog_binary
from bench.schema import Detection, Outcome, ScannerConfig
from bench.score import score

pytestmark = pytest.mark.target_spec


@pytest.fixture(scope="session")
def recovery_contract():
    corpus = IocRecoveryCorpus()
    if not corpus.manifest.is_file():
        pytest.fail(
            "IoC-recovery corpus is absent; run "
            "`make -C benchmarks ioc-recovery-corpus`"
        )
    records = corpus.records()
    expected = Counter(
        record.category
        for record in records
        if record.label and not record.ignore
    )
    if not expected:
        pytest.fail("IoC-recovery corpus contains no positive recovery records")
    return corpus, records, dict(sorted(expected.items()))


@pytest.fixture(scope="session")
def deep_recovery_detection(recovery_contract) -> Detection:
    corpus, records, _expected = recovery_contract
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
    return score(records, findings, corpus.file_root)


def _assert_exact_recovery(
    detection: Detection,
    expected: dict[str, int],
) -> None:
    outcome = detection.overall
    expected_total = sum(expected.values())
    assert (outcome.tp, outcome.fp, outcome.fn) == (expected_total, 0, 0), (
        "deep recovery target requires exact recovery without extra findings "
        f"across every positive fixture; expected TP={expected_total}, "
        f"got TP={outcome.tp}, FP={outcome.fp}, FN={outcome.fn}"
    )


def _assert_no_blind_recovery_category(
    detection: Detection,
    expected: dict[str, int],
) -> None:
    assert set(detection.per_category) == set(expected)
    failures = {
        category: (outcome.tp, outcome.fp, outcome.fn)
        for category, outcome in detection.per_category.items()
        if (outcome.tp, outcome.fp, outcome.fn)
        != (expected[category], 0, 0)
    }
    assert not failures, f"deep recovery category gaps: {failures}"


def test_deep_mode_recovers_every_plaintext_exactly(
    deep_recovery_detection: Detection,
    recovery_contract,
):
    _corpus, _records, expected = recovery_contract
    _assert_exact_recovery(deep_recovery_detection, expected)


def test_deep_mode_has_no_blind_recovery_category(
    deep_recovery_detection: Detection,
    recovery_contract,
):
    _corpus, _records, expected = recovery_contract
    _assert_no_blind_recovery_category(deep_recovery_detection, expected)


def test_deep_recovery_target_rejects_one_extra_finding():
    expected = {
        "recovery/phase/plaintext/checksum": 2,
        "recovery/phase/plaintext/fixed-prefix": 3,
    }
    detection = Detection(
        overall=Outcome(tp=5, fp=1, fn=0),
        per_category={
            "recovery/phase/plaintext/checksum": Outcome(tp=2, fp=1, fn=0),
            "recovery/phase/plaintext/fixed-prefix": Outcome(tp=3, fp=0, fn=0),
        },
    )

    with pytest.raises(AssertionError, match=r"FP=1"):
        _assert_exact_recovery(detection, expected)
    with pytest.raises(AssertionError, match=r"checksum.*2, 1, 0"):
        _assert_no_blind_recovery_category(detection, expected)


def test_deep_recovery_target_rejects_renamed_category():
    expected = {
        "recovery/phase/plaintext/checksum": 2,
        "recovery/phase/plaintext/fixed-prefix": 3,
    }
    detection = Detection(
        overall=Outcome(tp=5, fp=0, fn=0),
        per_category={
            "recovery/phase/plaintext/checksum": Outcome(tp=2, fp=0, fn=0),
            "recovery/phase/plaintext/renamed": Outcome(tp=3, fp=0, fn=0),
        },
    )

    with pytest.raises(AssertionError):
        _assert_no_blind_recovery_category(detection, expected)
