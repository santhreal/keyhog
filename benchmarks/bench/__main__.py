"""Command entrypoint for the benchmark package."""

from __future__ import annotations

import argparse
import json
import pathlib

from . import hardware
from .leaderboard import run_leaderboard
from .runner import resolve_corpus_with_root, run_once, write_result


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

    args = parser.parse_args(argv)
    if args.cmd == "host":
        return _host()
    if args.cmd == "corpus":
        return _corpus(args)
    if args.cmd == "run":
        return _run(args)
    if args.cmd == "leaderboard":
        return _leaderboard(args)
    parser.error(f"unknown command {args.cmd}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
