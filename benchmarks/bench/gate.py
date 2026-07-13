"""Regression + differential gate: the forcing function the nightly
workflows and the continuous-improvement loop run keyhog against.

This is the single replacement for the two retired gates:

* ``tools/diff_bench/run.py`` exited non-zero unless keyhog's F1 was
  *strictly* better than every available competitor's. That
  "differential" gate lives here as ``--beat-competitors`` (default on).
* a *regression* gate (new): keyhog's overall P/R/F1 must clear explicit
  floors (``--min-f1`` …) and/or must not drop below a committed baseline
  RunResult by more than ``--epsilon``. This is what
  ``benchmarks/results/baselines/*.json`` pin and what the production loop
  asserts after every calibrate→report cycle.

It sits ABOVE :func:`bench.leaderboard.run_leaderboard` (which produces the
per-scanner RunResult JSONs) and reuses :func:`bench.report.load_results` +
:func:`bench.report.canonical_leaderboard` so "which row is keyhog, which
are competitors" is decided by exactly the same newest-wins, default-config
selection the README leaderboard uses, the gate can never disagree with the
published table.

Exit code is the gate verdict: ``0`` all checks pass, ``1`` any violation,
``2`` keyhog itself is missing/unavailable (nothing to gate on, treated as a
hard failure so a broken build can't sneak through green).
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
import tempfile

from .keyhog_version import KeyhogVersionError, assert_version_matches_workspace
from .report import canonical_leaderboard, load_results
from .scanners import SCANNER_NAMES
from .schema import DetectorStat, RunResult

# Per-detector FP-regression tolerances. The overall-F1 baseline gate is blind
# to a single detector's FP spike that aggregate recall masks (the
# kubernetes-bootstrap-token retrain shipped +203 FP on one detector while
# overall CredData F1 *rose* 0.2539→0.2584, an aggregate gate would have
# passed it). A detector is flagged only when its FP growth clears BOTH an
# absolute floor (so low-count corpus noise is ignored) AND a relative floor
# (so proportional drift on an already-large detector is tolerated). A model
# regression like 5→208 trips both; a benign 100→125 trips neither.
DEFAULT_DETECTOR_FP_ABS = 20
DEFAULT_DETECTOR_FP_REL = 1.0


class GateError(Exception):
    """A gate precondition that makes the verdict undecidable (e.g. keyhog
    produced no result at all)."""


def _keyhog_row(rows: list[RunResult]) -> RunResult | None:
    for r in rows:
        if r.scanner.name == "keyhog":
            return r
    return None


def _assert_keyhog_results_current(rows: list[RunResult]) -> None:
    """Reject stale keyhog result artifacts before scoring a benchmark gate.

    The gate may consume existing JSON under benchmarks/results. Those files are
    useful only if they came from the same keyhog version as the workspace being
    gated; otherwise an old leaderboard can make a new tree look green.
    """
    for row in rows:
        if row.scanner.name != "keyhog":
            continue
        try:
            assert_version_matches_workspace(
                row.scanner.version,
                what="keyhog benchmark result",
            )
        except KeyhogVersionError as exc:
            raise GateError(f"{exc}; rerun `make leaderboard` with the current binary") from exc


def _baseline_keyhog_row(baseline: pathlib.Path, corpus: str) -> RunResult:
    """The keyhog RunResult a committed baseline pins for ``corpus``.

    ``baseline`` may be a single RunResult file or a directory of them;
    canonical selection picks the same keyhog row the live run would. The F1
    floor and the per-detector FP baseline both derive from this one row, so
    they can never disagree about which build is the baseline."""
    results = (
        load_results(baseline)
        if baseline.is_dir()
        else [RunResult.from_json(json.loads(baseline.read_text()))]
    )
    row = _keyhog_row(canonical_leaderboard(results, corpus))
    if row is None:
        raise GateError(f"baseline {baseline} has no keyhog result for corpus {corpus!r}")
    return row


def _baseline_keyhog_f1(baseline: pathlib.Path, corpus: str) -> float:
    """The keyhog overall-F1 a committed baseline pins for ``corpus``."""
    return _baseline_keyhog_row(baseline, corpus).detection.overall.f1()


def _detector_fp_regressions(
    keyhog: RunResult,
    baseline_detectors: dict[str, DetectorStat],
    max_abs: int,
    max_rel: float,
) -> list[str]:
    """Per-detector FP-regression violations (empty == none).

    A detector is flagged when its candidate FP exceeds the baseline FP by more
    than ``max_abs`` *and* by more than a ``max_rel`` fraction of the baseline
    (a detector absent from the baseline is treated as baseline FP 0, so any
    newly-firing detector above ``max_abs`` is flagged). This is the check the
    aggregate F1 gate cannot make."""
    out: list[str] = []
    for det, stat in sorted(keyhog.detection.per_detector.items()):
        cand = stat.fp
        present = det in baseline_detectors
        base = baseline_detectors[det].fp if present else 0
        if cand <= base:
            continue  # improved or unchanged
        abs_delta = cand - base
        if abs_delta <= max_abs:
            continue  # within absolute tolerance, corpus noise, not a spike
        rel = (abs_delta / base) if base > 0 else float("inf")
        if rel <= max_rel:
            continue  # proportional growth on an already-firing detector
        shape = "new" if base == 0 else f"{rel:.1f}x"
        out.append(
            f"detector {det!r} FP {base if present else 'absent'}→{cand} "
            f"(+{abs_delta}, {shape}) exceeds tolerance "
            f"(abs>{max_abs}, rel>{max_rel:.2f})"
        )
    return out


def evaluate(
    rows: list[RunResult],
    *,
    min_f1: float | None = None,
    min_precision: float | None = None,
    min_recall: float | None = None,
    beat_competitors: bool = True,
    baseline_f1: float | None = None,
    epsilon: float = 0.0,
    baseline_detectors: dict[str, DetectorStat] | None = None,
    max_detector_fp_abs: int = DEFAULT_DETECTOR_FP_ABS,
    max_detector_fp_rel: float = DEFAULT_DETECTOR_FP_REL,
    required_competitors: set[str] | None = None,
) -> list[str]:
    """Return the list of human-readable violations (empty == pass).

    Pure over the already-selected ``rows`` so it is unit-testable without a
    scanner binary or disk. When ``baseline_detectors`` is supplied, the
    per-detector FP-regression check runs in addition to the overall-F1
    baseline check, catching a single-detector spike the aggregate gate would
    pass."""
    keyhog = _keyhog_row(rows)
    if keyhog is None or not keyhog.available:
        reason = "no result" if keyhog is None else (keyhog.error or "unavailable")
        raise GateError(f"keyhog produced no usable result ({reason})")

    o = keyhog.detection.overall
    kf1, kp, kr = o.f1(), o.precision(), o.recall()
    violations: list[str] = []

    if min_f1 is not None and kf1 < min_f1:
        violations.append(f"F1 {kf1:.4f} < floor {min_f1:.4f}")
    if min_precision is not None and kp < min_precision:
        violations.append(f"precision {kp:.4f} < floor {min_precision:.4f}")
    if min_recall is not None and kr < min_recall:
        violations.append(f"recall {kr:.4f} < floor {min_recall:.4f}")

    if baseline_f1 is not None and kf1 < baseline_f1 - epsilon:
        violations.append(
            f"F1 {kf1:.4f} regressed below baseline {baseline_f1:.4f} "
            f"(epsilon {epsilon:.4f})"
        )

    if baseline_detectors is not None:
        violations.extend(_detector_fp_regressions(
            keyhog, baseline_detectors, max_detector_fp_abs, max_detector_fp_rel))

    if required_competitors:
        available = {
            r.scanner.name
            for r in rows
            if r.scanner.name != "keyhog" and r.available
        }
        for name in sorted(required_competitors - available):
            violations.append(f"required competitor {name!r} produced no usable result")

    if beat_competitors:
        for r in rows:
            if r.scanner.name == "keyhog" or not r.available:
                continue
            cf1 = r.detection.overall.f1()
            # Strictly better: a tie is a gate failure, matching the retired
            # diff_bench contract (keyhog must lead, not merely match).
            if cf1 >= kf1:
                violations.append(
                    f"{r.scanner.name} F1 {cf1:.4f} >= keyhog F1 {kf1:.4f} "
                    f"(keyhog must lead strictly)"
                )
    return violations


def _print_table(rows: list[RunResult]) -> None:
    print(f"{'scanner':<14}{'avail':<7}{'prec':>9}{'recall':>9}{'f1':>9}"
          f"{'findings':>10}", file=sys.stderr)
    print("-" * 58, file=sys.stderr)
    for r in rows:
        if not r.available:
            print(f"{r.scanner.name:<14}{'no':<7}{': ':>9}{': ':>9}{'. ':>9}"
                  f"{': ':>10}", file=sys.stderr)
            continue
        o = r.detection.overall
        print(f"{r.scanner.name:<14}{'yes':<7}{o.precision():>9.4f}"
              f"{o.recall():>9.4f}{o.f1():>9.4f}{r.finding_count:>10}",
              file=sys.stderr)


def run_gate(
    corpus: str,
    scanners: list[str],
    *,
    results_dir: pathlib.Path | None = None,
    min_f1: float | None = None,
    min_precision: float | None = None,
    min_recall: float | None = None,
    beat_competitors: bool = True,
    baseline: pathlib.Path | None = None,
    epsilon: float = 0.0,
    corpus_root: str | pathlib.Path | None = None,
    detector_fp_regression: bool = True,
    max_detector_fp_abs: int = DEFAULT_DETECTOR_FP_ABS,
    max_detector_fp_rel: float = DEFAULT_DETECTOR_FP_REL,
    required_competitors: set[str] | None = None,
) -> int:
    """Run (or load) a leaderboard, evaluate the gate, print the verdict.

    Returns the process exit code (0 pass / 1 violation / 2 undecidable)."""
    if results_dir is not None:
        results = load_results(results_dir)
    else:
        # Fresh run into a scratch dir so the gate never depends on stale
        # results/ state; the loop calls report separately to persist.
        from .leaderboard import run_leaderboard

        with tempfile.TemporaryDirectory(prefix="keyhog-gate-") as tmp:
            run_leaderboard(corpus, scanners, tier="quick",
                            corpus_root=corpus_root, out_dir=pathlib.Path(tmp),
                            verbose=True)
            results = load_results(pathlib.Path(tmp))

    rows = canonical_leaderboard(results, corpus)
    if not rows:
        print(f"GATE UNDECIDABLE: no results for corpus {corpus!r}", file=sys.stderr)
        return 2
    _print_table(rows)
    try:
        _assert_keyhog_results_current(rows)
    except GateError as exc:
        print(f"\nGATE UNDECIDABLE: {exc}", file=sys.stderr)
        return 2

    baseline_f1: float | None = None
    baseline_detectors: dict[str, DetectorStat] | None = None
    if baseline is not None:
        baseline_row = _baseline_keyhog_row(baseline, corpus)
        baseline_f1 = baseline_row.detection.overall.f1()
        if detector_fp_regression:
            baseline_detectors = dict(baseline_row.detection.per_detector)
    try:
        violations = evaluate(
            rows,
            min_f1=min_f1,
            min_precision=min_precision,
            min_recall=min_recall,
            beat_competitors=beat_competitors,
            baseline_f1=baseline_f1,
            epsilon=epsilon,
            baseline_detectors=baseline_detectors,
            max_detector_fp_abs=max_detector_fp_abs,
            max_detector_fp_rel=max_detector_fp_rel,
            required_competitors=required_competitors,
        )
    except GateError as exc:
        print(f"\nGATE UNDECIDABLE: {exc}", file=sys.stderr)
        return 2

    if violations:
        print(f"\nGATE FAILED ({len(violations)} violation(s)):", file=sys.stderr)
        for v in violations:
            print(f"  - {v}", file=sys.stderr)
        return 1
    keyhog = _keyhog_row(rows)
    assert keyhog is not None
    print(f"\nGATE PASSED: keyhog F1={keyhog.detection.overall.f1():.4f} "
          f"leads on corpus {corpus!r}", file=sys.stderr)
    return 0


def _main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Run the keyhog regression + "
                                 "differential bench gate.")
    ap.add_argument("--corpus", default="mirror")
    ap.add_argument("--scanners",
                    default=",".join(SCANNER_NAMES),
                    help="comma-separated scanner names to run when --results "
                         "is not given")
    ap.add_argument("--results", type=pathlib.Path, default=None,
                    help="consume existing RunResult JSONs from this dir "
                         "instead of running a fresh leaderboard")
    ap.add_argument("--corpus-root", default=None)
    ap.add_argument("--min-f1", type=float, default=None)
    ap.add_argument("--min-precision", type=float, default=None)
    ap.add_argument("--min-recall", type=float, default=None)
    ap.add_argument("--baseline", type=pathlib.Path, default=None,
                    help="committed RunResult (file or dir) keyhog must not "
                         "regress below on F1")
    ap.add_argument("--epsilon", type=float, default=0.0,
                    help="allowed F1 slack below the baseline before failing")
    ap.add_argument("--no-beat-competitors", action="store_true",
                    help="skip the strictly-better-than-every-competitor check "
                         "(regression-only gate)")
    ap.add_argument("--no-detector-fp-regression", action="store_true",
                    help="skip the per-detector FP-regression check against the "
                         "--baseline (the check the aggregate-F1 gate can't make)")
    ap.add_argument("--max-detector-fp-abs", type=int,
                    default=DEFAULT_DETECTOR_FP_ABS,
                    help="absolute per-detector FP increase tolerated vs baseline")
    ap.add_argument("--max-detector-fp-rel", type=float,
                    default=DEFAULT_DETECTOR_FP_REL,
                    help="relative per-detector FP increase (fraction of baseline) "
                         "tolerated vs baseline; a spike must clear BOTH to fail")
    ap.add_argument("--require-competitors", default="",
                    help="comma-separated competitor names that must produce usable results")
    args = ap.parse_args(argv)
    scanners = [s.strip() for s in args.scanners.split(",") if s.strip()]
    required_competitors = {s.strip() for s in args.require_competitors.split(",") if s.strip()}
    return run_gate(
        args.corpus,
        scanners,
        results_dir=args.results,
        min_f1=args.min_f1,
        min_precision=args.min_precision,
        min_recall=args.min_recall,
        beat_competitors=not args.no_beat_competitors,
        baseline=args.baseline,
        epsilon=args.epsilon,
        corpus_root=args.corpus_root,
        detector_fp_regression=not args.no_detector_fp_regression,
        max_detector_fp_abs=args.max_detector_fp_abs,
        max_detector_fp_rel=args.max_detector_fp_rel,
        required_competitors=required_competitors or None,
    )


if __name__ == "__main__":
    raise SystemExit(_main())
