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
selection the README leaderboard uses — the gate can never disagree with the
published table.

Exit code is the gate verdict: ``0`` all checks pass, ``1`` any violation,
``2`` keyhog itself is missing/unavailable (nothing to gate on, treated as a
hard failure so a broken build can't sneak through green).
"""

from __future__ import annotations

import argparse
import pathlib
import sys
import tempfile

from .report import canonical_leaderboard, load_results
from .schema import RunResult


class GateError(Exception):
    """A gate precondition that makes the verdict undecidable (e.g. keyhog
    produced no result at all)."""


def _keyhog_row(rows: list[RunResult]) -> RunResult | None:
    for r in rows:
        if r.scanner.name == "keyhog":
            return r
    return None


def _baseline_keyhog_f1(baseline: pathlib.Path, corpus: str) -> float:
    """The keyhog overall-F1 a committed baseline pins for ``corpus``.

    ``baseline`` may be a single RunResult file or a directory of them;
    canonical selection picks the same keyhog row the live run would."""
    results = (
        load_results(baseline)
        if baseline.is_dir()
        else [RunResult.from_json(__import__("json").loads(baseline.read_text()))]
    )
    row = _keyhog_row(canonical_leaderboard(results, corpus))
    if row is None:
        raise GateError(f"baseline {baseline} has no keyhog result for corpus {corpus!r}")
    return row.detection.overall.f1()


def evaluate(
    rows: list[RunResult],
    *,
    min_f1: float | None = None,
    min_precision: float | None = None,
    min_recall: float | None = None,
    beat_competitors: bool = True,
    baseline_f1: float | None = None,
    epsilon: float = 0.0,
) -> list[str]:
    """Return the list of human-readable violations (empty == pass).

    Pure over the already-selected ``rows`` so it is unit-testable without a
    scanner binary or disk."""
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

    if beat_competitors:
        for r in rows:
            if r.scanner.name == "keyhog" or not r.available:
                continue
            cf1 = r.detection.overall.f1()
            # Strictly better: a tie is a gate failure, matching the retired
            # diff_bench contract — keyhog must lead, not merely match.
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
            print(f"{r.scanner.name:<14}{'no':<7}{'—':>9}{'—':>9}{'—':>9}"
                  f"{'—':>10}", file=sys.stderr)
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

    baseline_f1 = (
        _baseline_keyhog_f1(baseline, corpus) if baseline is not None else None
    )
    try:
        violations = evaluate(
            rows,
            min_f1=min_f1,
            min_precision=min_precision,
            min_recall=min_recall,
            beat_competitors=beat_competitors,
            baseline_f1=baseline_f1,
            epsilon=epsilon,
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
                    default="keyhog,betterleaks,kingfisher,noseyparker,trufflehog,titus",
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
    args = ap.parse_args(argv)
    scanners = [s.strip() for s in args.scanners.split(",") if s.strip()]
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
    )


if __name__ == "__main__":
    raise SystemExit(_main())
