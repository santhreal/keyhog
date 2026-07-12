from bench.calibrate import (
    actionable,
    recommend,
    recommend_all,
    to_toml_overlay,
)
from bench.schema import CONF_BINS, DetectorStat


def _stat(tp_bins: dict[int, int], fp_bins: dict[int, int], unique_tp: int = 0):
    tp_hist = [0] * CONF_BINS
    fp_hist = [0] * CONF_BINS
    for b, n in tp_bins.items():
        tp_hist[b] = n
    for b, n in fp_bins.items():
        fp_hist[b] = n
    return DetectorStat(
        tp=sum(tp_hist), fp=sum(fp_hist), unique_tp=unique_tp,
        tp_hist=tp_hist, fp_hist=fp_hist,
    )


def test_clean_separation_yields_lossless_floor_just_below_tp():
    # 5 TP at conf ~0.80 (bin 16), 3 FP at conf ~0.40 (bin 8).
    stat = _stat({16: 5}, {8: 3})
    rec = recommend("aws-secret-access-key", stat)

    # Highest floor that loses no TP while cutting FP sits just under the TP bin.
    assert rec.lossless_floor == 0.80
    assert rec.lossless_fp_cut == 3
    assert rec.actionable

    # F1-optimal is the *minimal* floor that already removes every FP.
    assert rec.f1_floor == 0.45
    assert rec.f1_fp_cut == 3
    assert rec.f1_tp_lost == 0
    assert rec.f1_precision == 1.0


def test_no_false_positives_is_not_actionable():
    stat = _stat({10: 4}, {})
    rec = recommend("github-pat", stat)
    assert rec.lossless_floor == 0.0
    assert rec.lossless_fp_cut == 0
    assert not rec.actionable
    assert rec.f1_floor == 0.0  # nothing to cut, keep everything


def test_missing_confidence_blocks_lossless_threshold_advice():
    stat = DetectorStat(tp=1, fp=2)
    stat.fp_hist[2] = 1

    rec = recommend("partial-confidence", stat)

    assert rec.lossless_floor == 0.0
    assert rec.lossless_fp_cut == 0
    assert rec.f1_fp_cut == 0


def test_fp_only_detector_never_recommends_one_point_zero():
    stat = _stat({}, {2: 1})
    rec = recommend("fp-only", stat)

    assert rec.lossless_floor == 0.95
    assert rec.lossless_fp_cut == 1


def test_overlap_blocks_lossless_but_f1_trades_recall_for_precision():
    # 2 TP and 5 FP share bin 8; 3 more TP at bin 16. You cannot drop the FP
    # without also dropping the 2 colliding TP.
    stat = _stat({8: 2, 16: 3}, {8: 5})
    rec = recommend("generic-high-entropy-string", stat)

    assert rec.lossless_floor == 0.0          # no free win
    assert not rec.actionable

    # F1 prefers dropping bin 8 entirely: lose 2 TP, kill 5 FP, F1 0.667 -> 0.75.
    assert rec.f1_floor == 0.45
    assert rec.f1_tp_lost == 2
    assert rec.f1_fp_cut == 5
    assert rec.f1_precision == 1.0


def test_recommend_all_sorts_fp_heavy_first_and_skips_empty_detector():
    per_detector = {
        "": _stat({10: 1}, {10: 99}),            # competitor / no-id bucket
        "low-fp": _stat({16: 10}, {8: 1}),
        "high-fp": _stat({16: 10}, {8: 20}),
    }
    recs = recommend_all(per_detector)
    ids = [r.detector_id for r in recs]
    assert "" not in ids                          # empty bucket skipped
    assert ids == ["high-fp", "low-fp"]           # FP-heavy first


def test_toml_overlay_emits_only_lossless_wins():
    per_detector = {
        "winner": _stat({16: 5}, {8: 3}),         # lossless floor 0.80
        "blocked": _stat({8: 2, 16: 3}, {8: 5}),  # no lossless win
    }
    recs = recommend_all(per_detector)
    wins = actionable(recs)
    assert [r.detector_id for r in wins] == ["winner"]

    overlay = to_toml_overlay(recs)
    # The block is the exact edit for the detector's own file: a [detector]
    # table under a comment naming detectors/<id>.toml (coherent with the
    # header's instruction — not a `["<id>"]` table that mismatches it).
    assert "# detectors/winner.toml" in overlay
    assert "[detector]" in overlay
    assert "min_confidence = 0.8" in overlay
    assert "blocked" not in overlay


def test_overlay_handles_no_wins():
    overlay = to_toml_overlay([])
    assert "No lossless" in overlay
