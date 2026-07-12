"""Closed-loop per-detector ``min_confidence`` calibration.

keyhog detectors each carry a ``min_confidence`` floor in
``detectors/<id>.toml`` — the precision/recall knob the docs call "per-detector
fine tuning". Today those floors are hand-chosen from a few observed scores.
This module turns the labeled-corpus scorer's per-detector confidence
histograms (:class:`bench.schema.DetectorStat`) into a *measured*
recommendation: the floor that drops a detector's false positives without
losing its true positives.

The math is exact on the histogram grid. Bin ``k`` covers
``[k*0.05, (k+1)*0.05)`` (see :data:`bench.schema.CONF_BINS`), so applying a
floor ``τ = k*CONF_BIN_WIDTH`` drops exactly bins ``0..k-1`` and keeps
``k..N-1``. For each candidate floor we know precisely how many TP and FP
findings it would cut.

Two recommendations per detector:

* **lossless** — the *highest* floor that cuts ≥1 FP while losing **zero** TP.
  This is the safe win: a strictly-better precision at identical recall. The
  TOML overlay only emits these.
* **f1** — the floor maximising F1 over the detector's *own* findings
  (precision against that detector's FP, recall against its own catchable
  positives). This trades a little recall for precision; surfaced as advice,
  never auto-applied.

Pure functions over :class:`DetectorStat`; no I/O, no scanner, fully unit
tested in ``test_calibrate.py``.
"""

from __future__ import annotations

from dataclasses import dataclass

from .schema import CONF_BIN_WIDTH, CONF_BINS, DetectorStat


def _cut_below(hist: list[int], k: int) -> int:
    """Count in bins ``0..k-1`` — what a floor of ``k*CONF_BIN_WIDTH`` drops."""
    return sum(hist[:k])


def _floor(k: int) -> float:
    return round(k * CONF_BIN_WIDTH, 4)


@dataclass
class Recommendation:
    """A per-detector floor recommendation derived from one labeled run."""

    detector_id: str
    tp: int
    fp: int
    unique_tp: int
    current_precision: float

    # Safe win: highest floor losing 0 TP while cutting ≥1 FP. 0.0 == leave
    # the floor where it is (nothing to gain losslessly).
    lossless_floor: float
    lossless_fp_cut: int

    # F1-optimal floor over this detector's own findings (advice only).
    f1_floor: float
    f1_fp_cut: int
    f1_tp_lost: int
    f1_precision: float

    @property
    def actionable(self) -> bool:
        """A lossless floor that actually removes false positives."""
        return self.lossless_floor > 0.0 and self.lossless_fp_cut > 0


def recommend(detector_id: str, stat: DetectorStat) -> Recommendation:
    """Compute lossless + F1-optimal floors for one detector."""
    tp_hist, fp_hist = list(stat.tp_hist), list(stat.fp_hist)
    missing_tp = max(0, stat.tp - sum(tp_hist))
    missing_fp = max(0, stat.fp - sum(fp_hist))
    if missing_tp:
        # A TP without confidence is threshold-critical: any floor above zero
        # might drop it, so model it in the lowest bin.
        tp_hist[0] += missing_tp
    if missing_fp:
        # An FP without confidence cannot be proven removable by a confidence
        # floor, so model it as too high to cut losslessly.
        fp_hist[-1] += missing_fp
    total_tp = sum(tp_hist)
    total_fp = sum(fp_hist)

    # ── lossless: walk floors upward, keep the highest that loses no TP ──
    lossless_floor = 0.0
    lossless_fp_cut = 0
    for k in range(1, CONF_BINS):
        if _cut_below(tp_hist, k) != 0:
            break  # this floor would start dropping real detections — stop
        fp_cut = _cut_below(fp_hist, k)
        if fp_cut > 0:
            lossless_floor = _floor(k)
            lossless_fp_cut = fp_cut

    # ── F1-optimal over the detector's own findings ──
    best_k = 0
    best_f1 = -1.0
    for k in range(0, CONF_BINS):
        kept_tp = total_tp - _cut_below(tp_hist, k)
        kept_fp = total_fp - _cut_below(fp_hist, k)
        denom_p = kept_tp + kept_fp
        precision = kept_tp / denom_p if denom_p else 0.0
        recall = kept_tp / total_tp if total_tp else 0.0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
        if f1 > best_f1 + 1e-12:  # strict improvement → prefer the lower floor
            best_f1 = f1
            best_k = k
    f1_floor = _floor(best_k)
    f1_fp_cut = _cut_below(fp_hist, best_k)
    f1_tp_lost = _cut_below(tp_hist, best_k)
    kept_tp = total_tp - f1_tp_lost
    kept_fp = total_fp - f1_fp_cut
    f1_precision = kept_tp / (kept_tp + kept_fp) if (kept_tp + kept_fp) else 0.0

    return Recommendation(
        detector_id=detector_id,
        tp=stat.tp,
        fp=stat.fp,
        unique_tp=stat.unique_tp,
        current_precision=round(stat.precision(), 4),
        lossless_floor=lossless_floor,
        lossless_fp_cut=lossless_fp_cut,
        f1_floor=f1_floor,
        f1_fp_cut=f1_fp_cut,
        f1_tp_lost=f1_tp_lost,
        f1_precision=round(f1_precision, 4),
    )


def recommend_all(
    per_detector: dict[str, DetectorStat],
    *,
    skip_empty_detector: bool = True,
) -> list[Recommendation]:
    """Recommendations for every detector that fired, FP-heavy first.

    ``skip_empty_detector`` drops the ``""`` bucket (findings whose scanner
    reported no detector id — competitors), so the output is keyhog-only.
    """
    recs = [
        recommend(det_id, stat)
        for det_id, stat in per_detector.items()
        if not (skip_empty_detector and det_id == "")
    ]
    recs.sort(key=lambda r: (-r.fp, -r.tp, r.detector_id))
    return recs


def actionable(recs: list[Recommendation]) -> list[Recommendation]:
    """Only the recommendations that losslessly cut ≥1 FP, biggest cut first."""
    out = [r for r in recs if r.actionable]
    out.sort(key=lambda r: (-r.lossless_fp_cut, r.detector_id))
    return out


def to_toml_overlay(recs: list[Recommendation]) -> str:
    """A copy-pasteable overlay of the lossless floor bumps.

    Each block is the exact edit for ``detectors/<id>.toml`` — set
    ``min_confidence`` under ``[detector]``. Only lossless, FP-cutting
    recommendations are emitted (applying these cannot lose a TP on the
    corpus they were measured against).
    """
    wins = actionable(recs)
    if not wins:
        return "# No lossless min_confidence bumps available on this corpus.\n"
    lines = [
        "# Per-detector min_confidence overlay — measured, lossless on the",
        "# benchmark corpus (each floor cuts ≥1 FP, loses 0 TP). Each block below",
        "# is the exact edit for that detector's own detectors/<id>.toml: set",
        "# min_confidence under its [detector] table, then rebuild + re-score to",
        "# confirm. Generated by `bench calibrate`.",
        "",
    ]
    for r in wins:
        # Emit exactly what the target file wants — a `[detector]` table with the
        # floor — prefixed by the file it belongs in. (This overlay is a reference
        # list of per-file edits, not one loadable TOML: each block lands in a
        # different detectors/<id>.toml.)
        lines.append(
            f"# detectors/{r.detector_id}.toml: cuts {r.lossless_fp_cut} FP "
            f"(was P={r.current_precision:.3f}, tp={r.tp}, fp={r.fp})"
        )
        lines.append("[detector]")
        lines.append(f"min_confidence = {r.lossless_floor}")
        lines.append("")
    return "\n".join(lines)
