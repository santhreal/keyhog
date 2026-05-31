"""Command entrypoint for the benchmark package."""

from __future__ import annotations

import argparse
import json
import pathlib

from . import hardware
from .analyze import analyze as analyze_examples, print_report
from .leaderboard import run_leaderboard
from .report import build_sections, inject, load_results, write_reports
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

    analyze = sub.add_parser("analyze", help="Mine FP/FN examples for a scanner and corpus.")
    analyze.add_argument("--scanner", default="keyhog")
    analyze.add_argument("--corpus", default="mirror")
    analyze.add_argument("--scanner-bin", default=None)
    analyze.add_argument("--corpus-root", default=None)
    analyze.add_argument("--top", type=int, default=15, help="examples per category")

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
    if args.cmd == "analyze":
        return _analyze(args)
    parser.error(f"unknown command {args.cmd}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
