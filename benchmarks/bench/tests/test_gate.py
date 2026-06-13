import pytest

from bench import gate
from bench.schema import CorpusInfo, Detection, DetectorStat, Outcome, RunResult
from bench.schema import Scanner as ScannerRecord
from bench.schema import ScannerConfig


def _row(scanner: str, tp: int, fp: int, fn: int, *, available: bool = True,
         error: str = "", per_detector: dict[str, int] | None = None) -> RunResult:
    detectors = {
        det: DetectorStat(fp=fp_count) for det, fp_count in (per_detector or {}).items()
    }
    return RunResult(
        scanner=ScannerRecord(name=scanner, version="test", config=ScannerConfig()),
        corpus=CorpusInfo(name="mirror", fixture_count=10, labeled_positives=tp + fn),
        detection=Detection(overall=Outcome(tp=tp, fp=fp, fn=fn),
                            per_detector=detectors),
        finding_count=tp + fp,
        available=available,
        error=error,
    )


def test_gate_passes_when_keyhog_leads_every_competitor():
    rows = [
        _row("keyhog", tp=5, fp=0, fn=0),       # P=R=F1=1.0
        _row("trufflehog", tp=2, fp=2, fn=3),   # lower F1
        _row("kingfisher", tp=4, fp=4, fn=1),
    ]
    assert gate.evaluate(rows) == []


def test_gate_fails_on_a_competitor_tie():
    # Strictly-better contract: a tie is a failure, not a pass.
    rows = [
        _row("keyhog", tp=4, fp=1, fn=1),
        _row("trufflehog", tp=4, fp=1, fn=1),   # identical F1
    ]
    violations = gate.evaluate(rows)
    assert len(violations) == 1
    assert "trufflehog" in violations[0]
    assert ">=" in violations[0]


def test_gate_fails_when_a_competitor_beats_keyhog():
    rows = [
        _row("keyhog", tp=2, fp=2, fn=3),
        _row("titus", tp=5, fp=0, fn=0),
    ]
    violations = gate.evaluate(rows)
    assert any("titus" in v for v in violations)


def test_unavailable_competitor_is_ignored():
    rows = [
        _row("keyhog", tp=5, fp=0, fn=0),
        _row("kingfisher", tp=5, fp=0, fn=0, available=False, error="binary not found"),
    ]
    assert gate.evaluate(rows) == []


def test_floor_violations_are_reported_independently():
    rows = [_row("keyhog", tp=3, fp=3, fn=3)]  # P=R=F1=0.5
    violations = gate.evaluate(
        rows, min_f1=0.9, min_precision=0.9, min_recall=0.9, beat_competitors=False)
    assert len(violations) == 3
    assert any("F1" in v for v in violations)
    assert any("precision" in v for v in violations)
    assert any("recall" in v for v in violations)


def test_floors_pass_when_met():
    rows = [_row("keyhog", tp=5, fp=0, fn=0)]
    assert gate.evaluate(
        rows, min_f1=0.99, min_precision=0.99, min_recall=0.99,
        beat_competitors=False) == []


def test_baseline_regression_fails_outside_epsilon():
    rows = [_row("keyhog", tp=8, fp=2, fn=0)]  # F1 = 0.8889
    # baseline pinned higher; drop exceeds the slack.
    violations = gate.evaluate(rows, baseline_f1=0.95, epsilon=0.01,
                               beat_competitors=False)
    assert any("regressed below baseline" in v for v in violations)


def test_baseline_regression_within_epsilon_passes():
    rows = [_row("keyhog", tp=8, fp=2, fn=0)]  # F1 = 0.8889
    assert gate.evaluate(rows, baseline_f1=0.89, epsilon=0.01,
                         beat_competitors=False) == []


def test_no_beat_competitors_skips_differential_check():
    rows = [
        _row("keyhog", tp=2, fp=2, fn=3),
        _row("titus", tp=5, fp=0, fn=0),   # beats keyhog, but check disabled
    ]
    assert gate.evaluate(rows, beat_competitors=False) == []


def test_detector_fp_regression_fails_even_when_overall_f1_improves():
    # The exact shape of the reverted kubernetes-bootstrap-token retrain: one
    # detector spikes 5→208 FP while overall F1 *rises*. The aggregate-F1
    # baseline gate passes it; the per-detector gate must catch it.
    cand = _row("keyhog", tp=85, fp=25, fn=15,                # F1 ≈ 0.8095
                per_detector={"kubernetes-bootstrap-token": 208})
    base_detectors = {"kubernetes-bootstrap-token": DetectorStat(fp=5)}
    # Overall-F1-only view: no violation (0.8095 > baseline 0.80).
    assert gate.evaluate([cand], baseline_f1=0.80, beat_competitors=False) == []
    # With the per-detector baseline, the single-detector spike is caught.
    violations = gate.evaluate(
        [cand], baseline_f1=0.80, baseline_detectors=base_detectors,
        beat_competitors=False)
    assert len(violations) == 1
    assert "kubernetes-bootstrap-token" in violations[0]
    assert "5→208" in violations[0]


def test_detector_fp_within_absolute_tolerance_passes():
    cand = _row("keyhog", tp=5, fp=2, fn=0,
                per_detector={"aws-secret-access-key": 18})
    base = {"aws-secret-access-key": DetectorStat(fp=2)}  # +16 abs, under abs=20
    assert gate.evaluate([cand], baseline_detectors=base,
                         beat_competitors=False) == []


def test_detector_fp_proportional_growth_is_tolerated():
    # A large, already-firing detector growing proportionally with the corpus
    # (100→150, +50 abs but only 0.5x) is corpus drift, not a model spike.
    cand = _row("keyhog", tp=5, fp=2, fn=0,
                per_detector={"generic-password": 150})
    base = {"generic-password": DetectorStat(fp=100)}
    assert gate.evaluate([cand], baseline_detectors=base,
                         beat_competitors=False) == []


def test_new_detector_fp_above_absolute_floor_is_flagged():
    # A detector absent from the baseline that appears with FP above the floor
    # is a regression (baseline FP treated as 0 → relative growth infinite).
    cand = _row("keyhog", tp=5, fp=2, fn=0,
                per_detector={"slack-webhook": 60})
    violations = gate.evaluate([cand], baseline_detectors={},
                               beat_competitors=False)
    assert len(violations) == 1
    assert "slack-webhook" in violations[0]
    assert "absent→60" in violations[0]
    assert "new" in violations[0]


def test_detector_fp_thresholds_are_tunable():
    cand = _row("keyhog", tp=5, fp=2, fn=0,
                per_detector={"datadog-api-key": 40})
    base = {"datadog-api-key": DetectorStat(fp=10)}  # +30 abs, 3.0x
    # Default tolerances (abs 20 / rel 1.0): flagged.
    assert gate.evaluate([cand], baseline_detectors=base,
                         beat_competitors=False)
    # Loosened tolerances: the same delta is now within budget.
    assert gate.evaluate([cand], baseline_detectors=base, beat_competitors=False,
                         max_detector_fp_abs=50, max_detector_fp_rel=5.0) == []


def test_missing_keyhog_is_undecidable():
    rows = [_row("trufflehog", tp=5, fp=0, fn=0)]
    with pytest.raises(gate.GateError):
        gate.evaluate(rows)


def test_unavailable_keyhog_is_undecidable():
    rows = [_row("keyhog", tp=0, fp=0, fn=0, available=False, error="build failed")]
    with pytest.raises(gate.GateError):
        gate.evaluate(rows)
