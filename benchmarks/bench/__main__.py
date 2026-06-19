"""Command entrypoint for the benchmark package."""

from __future__ import annotations

import argparse
import json
import pathlib

from . import hardware
from .analyze import analyze as analyze_examples, print_report
from .leaderboard import run_leaderboard
from .report import (
    build_sections,
    inject,
    load_results,
    render_calibration,
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
    run_leaderboard(
        args.corpus,
        scanners,
        tier=args.tier,
        matrix_axes=axes,
        corpus_root=args.corpus_root,
        out_dir=args.out,
    )
    return 0


def _report(args: argparse.Namespace) -> int:
    import sys
    results = load_results(args.results)
    # --check is a read-only gate (is the README up to date?); it must NOT
    # rewrite reports/ as a side effect, or a CI/prerelease check run from stale
    # results/ silently degrades the committed rollups. Only write when rendering.
    if not args.check:
        write_reports(results, args.corpus, args.reports)
    if not (args.inject or args.check):
        return 0
    readme = pathlib.Path(args.readme)
    original = readme.read_text() if readme.exists() else ""
    updated = original
    for name, body in build_sections(results, args.corpus).items():
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
        raise SystemExit(f"corpus {args.corpus!r} is unlabeled — calibration needs labels")
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
        required_competitors={s.strip() for s in args.require_competitors.split(",") if s.strip()} or None,
    )


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
    leaderboard.add_argument("--scanners", default="keyhog,betterleaks,kingfisher,noseyparker,trufflehog,titus")
    leaderboard.add_argument("--tier", choices=("quick", "perf"), default="quick")
    leaderboard.add_argument("--matrix", default=None)
    leaderboard.add_argument("--corpus-root", default=None)
    leaderboard.add_argument("--out", type=pathlib.Path, default=None)

    report = sub.add_parser("report", help="Render benchmark markdown reports.")
    report.add_argument("--results", type=pathlib.Path, default=pathlib.Path("results"))
    report.add_argument("--reports", type=pathlib.Path, default=pathlib.Path("reports"))
    report.add_argument("--corpus", default="mirror")
    report.add_argument("--readme", type=pathlib.Path, default=_REPO_ROOT / "README.md",
                        help="README to inject generated tables into (between BENCH markers).")
    report.add_argument("--inject", action="store_true",
                        help="Rewrite the README between <!-- BENCH:* --> markers.")
    report.add_argument("--check", action="store_true",
                        help="Exit 1 if --inject would change the README (idempotence gate).")

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
                      default="keyhog,betterleaks,kingfisher,noseyparker,trufflehog,titus")
    gate.add_argument("--results", type=pathlib.Path, default=None,
                      help="consume existing RunResult JSONs instead of a fresh run")
    gate.add_argument("--corpus-root", default=None)
    gate.add_argument("--min-f1", type=float, default=None)
    gate.add_argument("--min-precision", type=float, default=None)
    gate.add_argument("--min-recall", type=float, default=None)
    gate.add_argument("--baseline", type=pathlib.Path, default=None,
                      help="committed RunResult (file or dir) keyhog must not "
                           "regress below on F1")
    gate.add_argument("--epsilon", type=float, default=0.0)
    gate.add_argument("--no-beat-competitors", action="store_true",
                      help="regression-only gate (skip the beat-competitors check)")
    gate.add_argument("--require-competitors", default="",
                      help="comma-separated competitor names that must produce usable results")

    cross_device = sub.add_parser(
        "cross-device",
        help="Render or gate cross-device benchmark results.")
    cross_device.add_argument("--root", type=pathlib.Path,
                              default=pathlib.Path("results-cross-device"))
    cross_device.add_argument("--corpus", default="mirror")
    cross_device.add_argument("--scanner", default=None)
    cross_device.add_argument("--dominance-gate", action="store_true",
                              help="require keyhog to beat BetterLeaks and Kingfisher fastest paths by the configured factor on every required OS")
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
    parser.error(f"unknown command {args.cmd}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
