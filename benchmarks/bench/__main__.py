"""Command entrypoint for the benchmark package."""

from __future__ import annotations

import argparse
import json

from . import hardware
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

    args = parser.parse_args(argv)
    if args.cmd == "host":
        return _host()
    if args.cmd == "corpus":
        return _corpus(args)
    if args.cmd == "run":
        return _run(args)
    parser.error(f"unknown command {args.cmd}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
