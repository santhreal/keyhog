"""Command entrypoint for the benchmark package."""

from __future__ import annotations

import argparse
import json

from . import hardware
from .corpora import resolve_corpus


def _host() -> int:
    print(json.dumps(hardware.capture().to_json(), indent=2, sort_keys=True))
    return 0


def _corpus(args: argparse.Namespace) -> int:
    corpus = resolve_corpus(args.name, root=args.root if args.name == "kernel" else None)
    info = corpus.info()
    print(json.dumps(info.to_json(), indent=2, sort_keys=True))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Benchmark helpers.")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("host", help="Print host hardware JSON.")

    corpus = sub.add_parser("corpus", help="Print corpus info JSON.")
    corpus.add_argument("name")
    corpus.add_argument("--root", default=None)

    args = parser.parse_args(argv)
    if args.cmd == "host":
        return _host()
    if args.cmd == "corpus":
        return _corpus(args)
    parser.error(f"unknown command {args.cmd}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
