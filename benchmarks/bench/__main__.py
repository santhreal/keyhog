"""Command entrypoint for the benchmark package."""

from __future__ import annotations

import argparse
import json
import pathlib
import sys

from . import hardware
from .analyze import analyze as analyze_examples, print_report
from .gate import DEFAULT_DETECTOR_FP_ABS, DEFAULT_DETECTOR_FP_REL
from .leaderboard import RequiredBenchmarkUnavailable, run_leaderboard
from .scanners import SCANNER_NAMES
from .report import (
    ReportEmptyError,
    ResultLoadError,
    ResultSelectionError,
    assert_reports_populated,
    build_sections,
    default_run_set_path,
    inject,
    load_results,
    load_run_set,
    missing_marker_sections,
    render_calibration,
    select_declared_results,
    stale_report_paths,
    write_calibration_reports,
    write_reports,
)
from .runner import resolve_corpus_with_root, run_once, write_result

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]


def _host() -> int:
    print(json.dumps(hardware.capture().to_json(), indent=2, sort_keys=True))
    return 0


def _corpus(args: argparse.Namespace) -> int:
    corpus = resolve_corpus_with_root(args.name, args.root)
    info = corpus.info()
    print(json.dumps(info.to_json(), indent=2, sort_keys=True))
    return 0


def _run(args: argparse.Namespace) -> int:
    result = run_once(
        scanner_name=args.scanner,
        corpus_name=args.corpus,
        scanner_binary=args.scanner_bin,
        corpus_root=args.corpus_root,
    )
    write_result(result, args.output)
    return 0 if result.available and not result.error else 1


def _leaderboard(args: argparse.Namespace) -> int:
    scanners = [s.strip() for s in args.scanners.split(",") if s.strip()]
    axes = [a.strip() for a in args.matrix.split(",")] if args.matrix else None
    try:
        run_leaderboard(
            args.corpus,
            scanners,
            tier=args.tier,
            matrix_axes=axes,
            corpus_root=args.corpus_root,
            out_dir=args.out,
            require_available=args.require_available,
        )
    except RequiredBenchmarkUnavailable as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2
    return 0


def _report(args: argparse.Namespace) -> int:
    try:
        results = load_results(args.results)
        run_set_path = args.run_set or default_run_set_path(args.results)
        if run_set_path is not None:
            results = select_declared_results(
                results,
                args.corpus,
                load_run_set(run_set_path),
            )
        assert_reports_populated(results, args.corpus)
    except (ReportEmptyError, ResultLoadError, ResultSelectionError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    # --check is a read-only gate (is the README up to date?); it must NOT
    # rewrite reports/ as a side effect, or a CI/prerelease check run from stale
    # results/ silently degrades the committed rollups. Only write when rendering.
    if not args.check:
        write_reports(results, args.corpus, args.reports)
    if not (args.inject or args.check):
        return 0
    readme = pathlib.Path(args.readme)
    original = readme.read_text() if readme.exists() else ""
    sections = build_sections(results, args.corpus)
    if args.check:
        absent = missing_marker_sections(original, list(sections))
        if absent:
            print(
                f"README is missing BENCH markers for: {', '.join(absent)} "
                f"(injection cannot run, restore the <!-- BENCH:*:start/end --> markers).",
                file=sys.stderr,
            )
            return 1
        stale_reports = stale_report_paths(
            results,
            args.corpus,
            args.reports,
        )
        if stale_reports:
            joined = ", ".join(str(path) for path in stale_reports)
            print(
                f"Benchmark reports are stale: `make report` would change {joined}.",
                file=sys.stderr,
            )
            return 1
    updated = original
    for name, body in sections.items():
        updated = inject(updated, name, body)
    if args.check:
        if updated != original:
            print("README bench tables are STALE: `make report` would change it.",
                  file=sys.stderr)
            return 1
        print("README bench tables are up to date.", file=sys.stderr)
        return 0
    if updated != original:
        readme.write_text(updated)
        print(f"injected bench tables into {readme}", file=sys.stderr)
    else:
        print("README unchanged (markers absent or already current).", file=sys.stderr)
    return 0


def _calibrate(args: argparse.Namespace) -> int:
    import sys

    from .scanners import resolve_scanner
    from .score import score

    corpus = resolve_corpus_with_root(args.corpus, args.corpus_root)
    records = corpus.records()
    if not records:
        raise SystemExit(f"corpus {args.corpus!r} is unlabeled, calibration needs labels")
    scanner = resolve_scanner(args.scanner, binary=args.scanner_bin)
    if not scanner.available():
        raise SystemExit(f"{args.scanner} binary not found: {scanner.binary}")

    findings, _stats = scanner.run(corpus.scan_root, scanner.default_config())
    detection = score(records, findings, corpus.file_root)
    positives = corpus.info().labeled_positives

    written = write_calibration_reports(
        detection, args.corpus, positives, args.reports)
    print(f"{args.scanner} on {args.corpus}: "
          f"{len(detection.per_detector)} detectors fired, "
          f"overall P={detection.overall.precision():.4f} "
          f"R={detection.overall.recall():.4f} "
          f"F1={detection.overall.f1():.4f}", file=sys.stderr)
    print(render_calibration(detection), file=sys.stderr)
    for name, path in written.items():
        print(f"wrote {path}", file=sys.stderr)
    if args.emit_toml:
        emit = pathlib.Path(args.emit_toml)
        emit.write_text(written["calibration.toml"].read_text())
        print(f"wrote overlay {emit}", file=sys.stderr)
    return 0


def _analyze(args: argparse.Namespace) -> int:
    import sys
    report = analyze_examples(
        args.scanner,
        args.corpus,
        corpus_root=args.corpus_root,
        scanner_binary=args.scanner_bin,
    )
    n_fn = sum(len(v) for v in report["fn"].values())
    n_fp = sum(len(v) for v in report["fp"].values())
    print(f"{args.scanner} on {args.corpus}: {n_fn} missed positives, "
          f"{n_fp} false fires", file=sys.stderr)
    print_report(report, args.top)
    return 0


def _gate(args: argparse.Namespace) -> int:
    from .gate import run_gate

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
        detector_fp_regression=not args.no_detector_fp_regression,
        max_detector_fp_abs=args.max_detector_fp_abs,
        max_detector_fp_rel=args.max_detector_fp_rel,
        required_competitors={s.strip() for s in args.require_competitors.split(",") if s.strip()} or None,
        speed_budgets=args.speed_budgets,
        speed_control_results=args.speed_control_results,
    )


def _profile_run(args: argparse.Namespace) -> int:
    """Run one paired control/candidate profiled trial set and write receipts."""
    import shlex
    import shutil
    import subprocess
    import time

    from . import hardware
    from .executable_snapshot import sha256_file
    from .keyhog_version import workspace_git_hash
    from .profile_capture import ProfileCaptureError, capture_profiled_run
    from .receipts import build_receipt
    from .trials import TrialOutcome, run_trials

    scan_args = shlex.split(args.scan_args)
    out_dir = pathlib.Path(args.out)
    cache_dir = pathlib.Path(args.cache_dir) if args.cache_dir else None

    def clear_caches() -> None:
        if cache_dir is not None and cache_dir.exists():
            shutil.rmtree(cache_dir)

    host = hardware.capture()
    for role, binary in (("control", args.control_bin), ("candidate", args.candidate_bin)):
        binary_path = pathlib.Path(binary)
        if not binary_path.exists():
            print(f"ERROR: {role} binary {binary} does not exist", file=sys.stderr)
            return 2

        def executor(state, index, _binary=binary_path, _role=role):
            if index < 0:
                # Untimed priming run: no artifact, its wall is not evidence.
                start = time.perf_counter()
                proc = subprocess.run([str(_binary), *scan_args],
                                      capture_output=True)
                if proc.returncode != 0:
                    raise ProfileCaptureError(
                        f"priming run exited {proc.returncode} for {_binary}"
                    )
                return TrialOutcome(
                    wall_ms=(time.perf_counter() - start) * 1000.0
                )
            profile_path = out_dir / _role / f"{state.value}-{index}-profile.json"
            outcome, _artifact = capture_profiled_run(
                binary=_binary,
                scan_args=scan_args,
                profile_path=profile_path,
            )
            return outcome

        try:
            trial_set = run_trials(
                workload=args.workload,
                role=role,
                executor=executor,
                cold=args.cold,
                warm=args.warm,
                steady=args.steady,
                pin_affinity=not args.no_affinity,
                governor_required=args.governor,
                clear_caches=clear_caches,
            )
        except ProfileCaptureError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 2
        receipt = build_receipt(
            trial_set,
            binary_sha256=sha256_file(binary_path.resolve(strict=True)),
            git_hash=workspace_git_hash(),
            host=host,
        )
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / f"{role}-{args.workload}-trials.json").write_text(
            json.dumps(trial_set.to_json(), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        (out_dir / f"{role}-{args.workload}-receipt.json").write_text(
            json.dumps(receipt.to_json(), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        invalid = sum(1 for trial in trial_set.trials if not trial.valid)
        print(f"{role}: {len(trial_set.trials)} trials ({invalid} invalid), "
              f"receipt digest {receipt.digest()}", file=sys.stderr)
    return 0


def _profile_matrix(args: argparse.Namespace) -> int:
    from .profile_matrix import MatrixError, load_matrix, plan_jobs

    try:
        matrix = load_matrix(args.matrix)
    except MatrixError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    jobs = plan_jobs(matrix)
    print(json.dumps([job.to_json() for job in jobs], indent=2, sort_keys=True))
    return 0


def _profile_gate(args: argparse.Namespace) -> int:
    """Profiler overhead and stage-regression budgets over captured artifacts."""
    from .profile_artifact import ProfileArtifactError, load_causal_profile
    from .profile_gates import (
        BudgetError,
        evaluate_overhead,
        evaluate_stage_regressions,
        load_budgets,
    )
    from .trials import TrialSet

    def load_trial_set(path: pathlib.Path) -> TrialSet:
        try:
            payload = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError) as exc:
            raise BudgetError(f"cannot load trial set {path}: {exc}") from exc
        try:
            return TrialSet.from_json(payload)
        except (KeyError, TypeError, ValueError) as exc:
            raise BudgetError(f"invalid trial set {path}: {exc}") from exc

    violations: list[str] = []
    try:
        budgets = load_budgets(args.budgets)
        if args.profiled_trials is not None or args.unprofiled_trials is not None:
            if args.profiled_trials is None or args.unprofiled_trials is None:
                raise BudgetError(
                    "the overhead gate needs both --profiled-trials and "
                    "--unprofiled-trials"
                )
            if budgets.overhead_max_ratio is None:
                raise BudgetError(
                    f"{args.budgets} declares no [profiler_overhead] budget"
                )
            profiled = load_trial_set(args.profiled_trials)
            unprofiled = load_trial_set(args.unprofiled_trials)
            if profiled.workload != unprofiled.workload:
                raise BudgetError(
                    f"overhead gate workload mismatch: {profiled.workload!r} vs "
                    f"{unprofiled.workload!r}; both legs must measure one workload"
                )
            profiled_walls = profiled.valid_wall_ms()
            unprofiled_walls = unprofiled.valid_wall_ms()
            if not profiled_walls or not unprofiled_walls:
                raise BudgetError(
                    "overhead gate has no valid trials "
                    f"(profiled {len(profiled_walls)}, unprofiled "
                    f"{len(unprofiled_walls)}); invalid trials are never "
                    "silently retried"
                )
            verdict = evaluate_overhead(
                profiled_walls,
                unprofiled_walls,
                max_ratio=budgets.overhead_max_ratio,
                seed=args.seed,
            )
            violations.extend(verdict.violations)
        if args.control_profile is not None or args.candidate_profile is not None:
            if args.control_profile is None or args.candidate_profile is None:
                raise BudgetError(
                    "the stage gate needs both --control-profile and "
                    "--candidate-profile"
                )
            if not args.workflow:
                raise BudgetError("the stage gate needs --workflow")
            budget = budgets.workflows.get(args.workflow)
            if budget is None:
                raise BudgetError(
                    f"{args.budgets} declares no workflow {args.workflow!r} budget"
                )
            if not budget.stages:
                raise BudgetError(
                    f"workflow {args.workflow!r} declares no stage budgets"
                )
            control = load_causal_profile(args.control_profile)
            candidate = load_causal_profile(args.candidate_profile)
            violations.extend(evaluate_stage_regressions(control, candidate, budget))
        if args.profiled_trials is None and args.control_profile is None:
            raise BudgetError(
                "no gate selected: pass --profiled-trials/--unprofiled-trials "
                "and/or --control-profile/--candidate-profile"
            )
    except (BudgetError, ProfileArtifactError) as exc:
        print(f"PROFILE GATE UNDECIDABLE: {exc}", file=sys.stderr)
        return 2

    if violations:
        print(f"PROFILE GATE FAILED ({len(violations)} violation(s)):",
              file=sys.stderr)
        for violation in violations:
            print(f"  - {violation}", file=sys.stderr)
        return 1
    print("PROFILE GATE PASSED", file=sys.stderr)
    return 0


def _cross_device(args: argparse.Namespace) -> int:
    from . import cross_compare

    rows = cross_compare.rows_for(args.root, args.corpus, None)
    if args.dominance_gate:
        required_oses = tuple(s.strip().lower() for s in args.required_oses.split(",") if s.strip())
        verdict = cross_compare.evaluate_dominance(
            rows,
            factor=args.factor,
            required_oses=required_oses,
        )
        print(cross_compare.render_dominance(verdict))
        return 0 if verdict.ok else 1
    filtered = rows
    if args.scanner:
        filtered = [(device, r) for device, r in rows if r.scanner.name == args.scanner]
    print(cross_compare.render(filtered))
    return 0 if filtered else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Benchmark helpers.")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("host", help="Print host hardware JSON.")

    corpus = sub.add_parser("corpus", help="Print corpus info JSON.")
    corpus.add_argument("name")
    corpus.add_argument("--root", default=None)

    run = sub.add_parser("run", help="Run one scanner/corpus benchmark and emit RunResult JSON.")
    run.add_argument("scanner")
    run.add_argument("corpus")
    run.add_argument("--scanner-bin", default=None)
    run.add_argument("--corpus-root", default=None)
    run.add_argument("--output", default="-")

    leaderboard = sub.add_parser("leaderboard", help="Run a scanner leaderboard matrix.")
    leaderboard.add_argument("--corpus", default="mirror")
    leaderboard.add_argument("--scanners", default=",".join(SCANNER_NAMES))
    leaderboard.add_argument("--tier", choices=("quick", "perf"), default="quick")
    leaderboard.add_argument("--matrix", default=None)
    leaderboard.add_argument("--corpus-root", default=None)
    leaderboard.add_argument("--out", type=pathlib.Path, default=None)
    leaderboard.add_argument(
        "--require-available",
        action="store_true",
        help="write every row, then exit nonzero if any requested row could not execute",
    )

    report = sub.add_parser("report", help="Render benchmark markdown reports.")
    report.add_argument("--results", type=pathlib.Path, default=pathlib.Path("results"))
    report.add_argument("--reports", type=pathlib.Path, default=pathlib.Path("reports"))
    report.add_argument("--corpus", default="mirror")
    report.add_argument(
        "--run-set",
        type=pathlib.Path,
        default=None,
        help=(
            "TOML inventory binding rows to paths relative to --results and exact identities. "
            "The committed results directory uses run-sets/canonical.toml by default."
        ),
    )
    report.add_argument("--readme", type=pathlib.Path, default=_REPO_ROOT / "README.md",
                        help="README to inject generated tables into (between BENCH markers).")
    report.add_argument("--inject", action="store_true",
                        help="Rewrite the README between <!-- BENCH:* --> markers.")
    report.add_argument("--check", action="store_true",
                        help="Exit 1 if reports or the README would change (idempotence gate).")

    calibrate = sub.add_parser(
        "calibrate",
        help="Per-detector P/R/F1 + measured min_confidence floor recommendations.")
    calibrate.add_argument("--scanner", default="keyhog")
    calibrate.add_argument("--corpus", default="mirror")
    calibrate.add_argument("--scanner-bin", default=None)
    calibrate.add_argument("--corpus-root", default=None)
    calibrate.add_argument("--reports", type=pathlib.Path, default=pathlib.Path("reports"))
    calibrate.add_argument("--emit-toml", default=None,
                           help="Also write the lossless min_confidence overlay here.")

    analyze = sub.add_parser("analyze", help="Mine FP/FN examples for a scanner and corpus.")
    analyze.add_argument("--scanner", default="keyhog")
    analyze.add_argument("--corpus", default="mirror")
    analyze.add_argument("--scanner-bin", default=None)
    analyze.add_argument("--corpus-root", default=None)
    analyze.add_argument("--top", type=int, default=15, help="examples per category")

    gate = sub.add_parser(
        "gate",
        help="Regression + differential gate: keyhog must lead every competitor "
             "and clear F1/P/R floors (exit 1 on violation, 2 if undecidable).")
    gate.add_argument("--corpus", default="mirror")
    gate.add_argument("--scanners",
                      default=",".join(SCANNER_NAMES))
    gate.add_argument("--results", type=pathlib.Path, default=None,
                      help="consume existing RunResult JSONs instead of a fresh run")
    gate.add_argument("--corpus-root", default=None)
    gate.add_argument("--min-f1", type=float, default=None)
    gate.add_argument("--min-precision", type=float, default=None)
    gate.add_argument("--min-recall", type=float, default=None)
    gate.add_argument("--baseline", type=pathlib.Path, default=None,
                      help="committed RunResult (file) or baselines directory "
                           "containing canonical.toml; keyhog must not regress below on F1")
    gate.add_argument("--epsilon", type=float, default=0.0)
    gate.add_argument("--no-beat-competitors", action="store_true",
                      help="regression-only gate (skip the beat-competitors check)")
    gate.add_argument("--no-detector-fp-regression", action="store_true",
                      help="skip the per-detector FP-regression check against the "
                           "--baseline (the check the aggregate-F1 gate can't make)")
    gate.add_argument("--max-detector-fp-abs", type=int,
                      default=DEFAULT_DETECTOR_FP_ABS,
                      help="absolute per-detector FP increase tolerated vs baseline")
    gate.add_argument("--max-detector-fp-rel", type=float,
                      default=DEFAULT_DETECTOR_FP_REL,
                      help="relative per-detector FP increase (fraction of baseline) "
                           "tolerated vs baseline; a spike must clear BOTH to fail")
    gate.add_argument("--require-competitors", default="",
                      help="comma-separated competitor names that must produce usable results")
    gate.add_argument("--speed-budgets", type=pathlib.Path, default=None,
                      help="TOML budget file; enables the per-workflow-class "
                           "end-to-end speed gate (requires --speed-control-results)")
    gate.add_argument("--speed-control-results", type=pathlib.Path, default=None,
                      help="directory of control RunResult JSONs the candidate "
                           "rows are compared against for speed budgets")

    profile_run = sub.add_parser(
        "profile-run",
        help="Run a paired control/candidate profiled trial set and write "
             "trial sets, profile artifacts, and provenance receipts.")
    profile_run.add_argument("--control-bin", required=True)
    profile_run.add_argument("--candidate-bin", required=True)
    profile_run.add_argument("--workload", required=True)
    profile_run.add_argument("--scan-args", required=True,
                             help="scan argument string shared by both binaries; "
                                  "--profile-out is appended per run")
    profile_run.add_argument("--out", required=True,
                             help="output directory for artifacts, trial sets, receipts")
    profile_run.add_argument("--cold", type=int, default=1)
    profile_run.add_argument("--warm", type=int, default=1)
    profile_run.add_argument("--steady", type=int, default=3)
    profile_run.add_argument("--cache-dir", default=None,
                             help="keyhog cache directory cleared before cold trials")
    profile_run.add_argument("--no-affinity", action="store_true",
                             help="do not request affinity pinning (trials record "
                                  "the control as not requested)")
    profile_run.add_argument("--governor", default="",
                             help="required CPU governor (e.g. performance); trials "
                                  "on any other governor are invalid")

    profile_matrix = sub.add_parser(
        "profile-matrix",
        help="Expand the nightly profiling matrix into its deterministic job plan.")
    profile_matrix.add_argument(
        "--matrix", type=pathlib.Path,
        default=pathlib.Path("profile-matrix/nightly.toml"))

    profile_gate = sub.add_parser(
        "profile-gate",
        help="Profiler overhead and stage-regression budgets over captured "
             "artifacts (exit 1 on violation, 2 if undecidable).")
    profile_gate.add_argument("--budgets", type=pathlib.Path, required=True)
    profile_gate.add_argument("--workflow", default=None)
    profile_gate.add_argument("--control-profile", type=pathlib.Path, default=None)
    profile_gate.add_argument("--candidate-profile", type=pathlib.Path, default=None)
    profile_gate.add_argument("--profiled-trials", type=pathlib.Path, default=None,
                              help="TrialSet JSON of profiled runs (overhead gate)")
    profile_gate.add_argument("--unprofiled-trials", type=pathlib.Path, default=None,
                              help="TrialSet JSON of unprofiled runs (overhead gate)")
    profile_gate.add_argument("--seed", type=int, default=0,
                              help="bootstrap seed for the overhead intervals")

    cross_device = sub.add_parser(
        "cross-device",
        help="Render or gate cross-device benchmark results.")
    cross_device.add_argument("--root", type=pathlib.Path,
                              default=pathlib.Path("results-cross-device"))
    cross_device.add_argument("--corpus", default="mirror")
    cross_device.add_argument("--scanner", default=None)
    cross_device.add_argument("--dominance-gate", action="store_true",
                              help="require keyhog to beat Betterleaks and Kingfisher fastest paths by the configured factor on every required OS")
    cross_device.add_argument("--factor", type=float, default=10.0)
    cross_device.add_argument("--required-oses", default="linux,macos,windows")

    args = parser.parse_args(argv)
    if args.cmd == "host":
        return _host()
    if args.cmd == "corpus":
        return _corpus(args)
    if args.cmd == "run":
        return _run(args)
    if args.cmd == "leaderboard":
        return _leaderboard(args)
    if args.cmd == "report":
        return _report(args)
    if args.cmd == "calibrate":
        return _calibrate(args)
    if args.cmd == "analyze":
        return _analyze(args)
    if args.cmd == "gate":
        return _gate(args)
    if args.cmd == "cross-device":
        return _cross_device(args)
    if args.cmd == "profile-run":
        return _profile_run(args)
    if args.cmd == "profile-matrix":
        return _profile_matrix(args)
    if args.cmd == "profile-gate":
        return _profile_gate(args)
    parser.error(f"unknown command {args.cmd}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
