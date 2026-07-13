import json

import pytest

from bench import gate
from bench.keyhog_version import (
    workspace_detector_digest,
    workspace_git_hash,
    workspace_keyhog_version,
)
from bench.schema import CorpusInfo, Detection, DetectorStat, Outcome, RunResult
from bench.schema import Scanner as ScannerRecord
from bench.schema import ScannerConfig


@pytest.fixture(autouse=True)
def _clean_tracked_workspace(monkeypatch):
    monkeypatch.setattr(gate, "assert_workspace_tracked_tree_clean", lambda: None)
    monkeypatch.setattr(
        gate, "_current_keyhog_executable_sha256", lambda: "a" * 64,
    )


def _current_keyhog_version_record() -> str:
    return (
        f"KeyHog v{workspace_keyhog_version()}\n"
        f"Commit: {workspace_git_hash()}\n"
        f"Detector Set: 1 ({workspace_detector_digest()})\n"
        "Build Target: test"
    )


def _row(scanner: str, tp: int, fp: int, fn: int, *, available: bool = True,
         error: str = "", per_detector: dict[str, int] | None = None,
         version: str = "test", executable_sha256: str | None = None,
         detector_corpus_sha256: str = "") -> RunResult:
    detectors = {
        det: DetectorStat(fp=fp_count) for det, fp_count in (per_detector or {}).items()
    }
    return RunResult(
        scanner=ScannerRecord(
            name=scanner, version=version, config=ScannerConfig(),
            executable_sha256=(
                "a" * 64 if executable_sha256 is None and scanner == "keyhog"
                else executable_sha256 or ""
            ),
            detector_corpus_sha256=detector_corpus_sha256,
        ),
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


def test_required_competitor_missing_or_unavailable_fails():
    rows = [
        _row("keyhog", tp=5, fp=0, fn=0),
        _row("kingfisher", tp=5, fp=0, fn=0, available=False, error="binary not found"),
    ]
    violations = gate.evaluate(
        rows,
        required_competitors={"betterleaks", "kingfisher"},
    )
    assert "required competitor 'betterleaks' produced no usable result" in violations
    assert "required competitor 'kingfisher' produced no usable result" in violations


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


def test_run_gate_rejects_stale_keyhog_result_artifacts(tmp_path):
    stale = _row("keyhog", tp=5, fp=0, fn=0, version="KeyHog v0.0.0 Build Target: test")
    (tmp_path / "mirror-keyhog-default.json").write_text(json.dumps(stale.to_json()))

    rc = gate.run_gate(
        "mirror",
        ["keyhog"],
        results_dir=tmp_path,
        beat_competitors=False,
    )

    assert rc == 2


@pytest.mark.parametrize("observed", [None, "bench-v999"])
def test_run_gate_is_undecidable_for_incompatible_result_schema(
    tmp_path, capsys, observed
):
    payload = _row("keyhog", tp=5, fp=0, fn=0).to_json()
    if observed is None:
        payload.pop("schema_version")
    else:
        payload["schema_version"] = observed
    artifact = tmp_path / "mirror-keyhog-default.json"
    artifact.write_text(json.dumps(payload))

    rc = gate.run_gate(
        "mirror", ["keyhog"], results_dir=tmp_path, beat_competitors=False,
    )

    assert rc == 2
    error = capsys.readouterr().err
    assert str(artifact) in error
    assert "supported='bench-v2'" in error


def test_run_gate_accepts_current_keyhog_result_artifacts(monkeypatch, tmp_path):
    digest = "d" * 64
    monkeypatch.setattr(gate, "workspace_detector_corpus_sha256", lambda: digest)
    current = _row(
        "keyhog",
        tp=5,
        fp=0,
        fn=0,
        version=_current_keyhog_version_record(),
        detector_corpus_sha256=digest,
    )
    (tmp_path / "mirror-keyhog-default.json").write_text(json.dumps(current.to_json()))

    rc = gate.run_gate(
        "mirror",
        ["keyhog"],
        results_dir=tmp_path,
        beat_competitors=False,
    )

    assert rc == 0


def test_run_gate_rejects_same_version_result_from_another_commit(
    monkeypatch, tmp_path, capsys
):
    digest = "d" * 64
    monkeypatch.setattr(gate, "workspace_detector_corpus_sha256", lambda: digest)
    stale_version = _current_keyhog_version_record().replace(
        f"Commit: {workspace_git_hash()}", f"Commit: {'0' * 40}"
    )
    stale = _row(
        "keyhog", tp=5, fp=0, fn=0,
        version=stale_version,
        detector_corpus_sha256=digest,
    )
    (tmp_path / "mirror-keyhog-default.json").write_text(json.dumps(stale.to_json()))

    rc = gate.run_gate(
        "mirror", ["keyhog"], results_dir=tmp_path, beat_competitors=False,
    )

    assert rc == 2
    assert "commit=" in capsys.readouterr().err


@pytest.mark.parametrize("observed", ["", "e" * 64])
def test_run_gate_rejects_missing_or_stale_detector_corpus_digest(
    monkeypatch, tmp_path, observed
):
    expected = "f" * 64
    monkeypatch.setattr(gate, "workspace_detector_corpus_sha256", lambda: expected)
    current = _row(
        "keyhog", tp=5, fp=0, fn=0,
        version=_current_keyhog_version_record(),
        detector_corpus_sha256=observed,
    )
    (tmp_path / "mirror-keyhog-default.json").write_text(json.dumps(current.to_json()))

    rc = gate.run_gate(
        "mirror", ["keyhog"], results_dir=tmp_path, beat_competitors=False,
    )

    assert rc == 2


@pytest.mark.parametrize("observed", ["", "not-a-sha", "A" * 64])
def test_run_gate_rejects_missing_or_malformed_executable_digest(
    monkeypatch, tmp_path, observed
):
    digest = "f" * 64
    monkeypatch.setattr(gate, "workspace_detector_corpus_sha256", lambda: digest)
    current = _row(
        "keyhog", tp=5, fp=0, fn=0,
        version=_current_keyhog_version_record(),
        executable_sha256=observed,
        detector_corpus_sha256=digest,
    )
    (tmp_path / "mirror-keyhog-default.json").write_text(json.dumps(current.to_json()))

    rc = gate.run_gate(
        "mirror", ["keyhog"], results_dir=tmp_path, beat_competitors=False,
    )

    assert rc == 2


def test_run_gate_rejects_well_formed_digest_from_another_executable(
    monkeypatch, tmp_path
):
    digest = "f" * 64
    monkeypatch.setattr(gate, "workspace_detector_corpus_sha256", lambda: digest)
    current = _row(
        "keyhog", tp=5, fp=0, fn=0,
        version=_current_keyhog_version_record(),
        executable_sha256="b" * 64,
        detector_corpus_sha256=digest,
    )
    (tmp_path / "mirror-keyhog-default.json").write_text(json.dumps(current.to_json()))

    rc = gate.run_gate(
        "mirror", ["keyhog"], results_dir=tmp_path, beat_competitors=False,
    )

    assert rc == 2


def test_run_gate_reports_broken_workspace_detector_corpus(monkeypatch, tmp_path, capsys):
    current = _row(
        "keyhog", tp=5, fp=0, fn=0,
        version=_current_keyhog_version_record(),
        detector_corpus_sha256="f" * 64,
    )
    (tmp_path / "mirror-keyhog-default.json").write_text(json.dumps(current.to_json()))
    monkeypatch.setattr(
        gate, "workspace_detector_corpus_sha256",
        lambda: (_ for _ in ()).throw(gate.KeyhogVersionError("detectors are unreadable")),
    )

    rc = gate.run_gate(
        "mirror", ["keyhog"], results_dir=tmp_path, beat_competitors=False,
    )

    assert rc == 2
    error = capsys.readouterr().err
    assert "repair the workspace detector corpus" in error
    assert "rerun `make leaderboard`" not in error


def test_run_gate_rejects_current_source_results_from_dirty_workspace(
    monkeypatch, tmp_path, capsys
):
    current = _row(
        "keyhog", tp=5, fp=0, fn=0,
        version=_current_keyhog_version_record(),
        detector_corpus_sha256="f" * 64,
    )
    (tmp_path / "mirror-keyhog-default.json").write_text(json.dumps(current.to_json()))
    monkeypatch.setattr(
        gate,
        "assert_workspace_tracked_tree_clean",
        lambda: (_ for _ in ()).throw(
            gate.KeyhogVersionError("tracked workspace has uncommitted changes")
        ),
    )

    rc = gate.run_gate(
        "mirror", ["keyhog"], results_dir=tmp_path, beat_competitors=False,
    )

    assert rc == 2
    assert "cannot accept current-source benchmark evidence" in capsys.readouterr().err
