"""Leaderboard orchestration: run many scanners (and keyhog config variants)
over a corpus, write one RunResult JSON per run, and rank them.

This sits ABOVE :func:`bench.runner.run_once` (single measurement) and below
:mod:`bench.report` (markdown rendering). It owns the matrix - which scanners,
which configs - and the results-on-disk layout
``results/<host_hash>/<corpus>-<scanner>-<config_id>.json`` that the report
generator consumes. Every scanner is scored on the *same* corpus
``scan_root`` (manifest-free) so the comparison is apples-to-apples.

Tiers:

* ``quick`` - every scanner at its default config (the README leaderboard).
* ``perf``  - keyhog's backend x cache x mode tree matrix, or its constrained
  backend x daemon matrix on the single-file daemon corpus.
"""

from __future__ import annotations

import argparse
import pathlib
import sys

from . import hardware
from .runner import (
    _run_resolved_scanner,
    resolve_corpus_with_root,
    write_result,
)
from .scanners import SCANNER_NAMES, resolve_scanner
from .scanners.keyhog import KeyhogScanner
from .schema import RunResult, ScannerConfig

_DEFAULT_SCANNERS = list(SCANNER_NAMES)


def results_dir(base: pathlib.Path | None = None) -> pathlib.Path:
    base = base or (pathlib.Path(__file__).resolve().parents[1] / "results")
    return base / hardware.capture().hostname_hash


def _configs_for(
    scanner_name: str,
    tier: str,
    matrix_axes: list[str] | None,
    corpus_name: str,
) -> list[ScannerConfig]:
    sc = resolve_scanner(scanner_name)
    if scanner_name == "keyhog" and tier == "perf":
        assert isinstance(sc, KeyhogScanner)
        default_axes = (
            ["backend", "daemon"]
            if corpus_name in {"daemon-file", "daemon_file"}
            else ["backend", "cache", "mode"]
        )
        configs = sc.matrix(matrix_axes or default_axes)
        if matrix_axes is None and corpus_name in {"daemon-file", "daemon_file"}:
            configs = [
                cfg for cfg in configs
                if cfg.daemon == "off" or cfg.backend != "auto"
            ]
        return configs
    if scanner_name == "keyhog" and matrix_axes:
        assert isinstance(sc, KeyhogScanner)
        return sc.matrix(matrix_axes)
    return [sc.default_config()]


def run_one(scanner_name: str, corpus_name: str, cfg: ScannerConfig,
            corpus_root: str | pathlib.Path | None = None,
            scanner_binary: str | None = None) -> RunResult:
    """One (scanner, config, corpus) measurement -> RunResult. Mirrors
    runner.run_once but lets the caller pin a specific config (not just the
    default) for the matrix."""
    scanner = resolve_scanner(scanner_name, binary=scanner_binary)
    corpus = resolve_corpus_with_root(corpus_name, corpus_root)
    return _run_resolved_scanner(scanner, scanner.version(), cfg, corpus)


def run_leaderboard(corpus_name: str, scanners: list[str], *, tier: str = "quick",
                    matrix_axes: list[str] | None = None,
                    corpus_root: str | pathlib.Path | None = None,
                    out_dir: pathlib.Path | None = None,
                    verbose: bool = True) -> list[pathlib.Path]:
    """Run the matrix, write one RunResult JSON per run, return their paths."""
    out = out_dir or results_dir()
    out.mkdir(parents=True, exist_ok=True)
    written: list[pathlib.Path] = []
    for scanner_name in scanners:
        for cfg in _configs_for(scanner_name, tier, matrix_axes, corpus_name):
            if verbose:
                print(f"> {scanner_name} [{cfg.config_id}] on {corpus_name}...",
                      file=sys.stderr)
            result = run_one(scanner_name, corpus_name, cfg, corpus_root=corpus_root)
            path = out / f"{corpus_name}-{scanner_name}-{cfg.config_id}.json"
            write_result(result, path)
            written.append(path)
            if verbose:
                _print_line(result)
    if verbose:
        print(f"\nwrote {len(written)} result(s) -> {out}", file=sys.stderr)
    return written


def _print_line(r: RunResult) -> None:
    if not r.available:
        print(f"  {r.scanner.name}: UNAVAILABLE - {r.error}", file=sys.stderr)
        return
    o = r.detection.overall
    wall = r.speed.wall_ms / 1000.0
    print(f"  {r.scanner.name:12} [{r.scanner.config_id}] "
          f"P={o.precision():.4f} R={o.recall():.4f} F1={o.f1():.4f} "
          f"({wall:.1f}s, {r.finding_count} findings, {r.speed.peak_rss_kb // 1024}MB)",
          file=sys.stderr)


def _main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Run a scanner leaderboard over a corpus.")
    ap.add_argument("--corpus", default="mirror")
    ap.add_argument("--scanners", default=",".join(_DEFAULT_SCANNERS),
                    help="comma-separated scanner names")
    ap.add_argument("--tier", choices=("quick", "perf"), default="quick")
    ap.add_argument("--matrix", default=None,
                    help="comma-separated keyhog axes: backend,cache,daemon,mode")
    ap.add_argument("--corpus-root", default=None)
    ap.add_argument("--out", default=None)
    args = ap.parse_args(argv)
    scanners = [s.strip() for s in args.scanners.split(",") if s.strip()]
    axes = [a.strip() for a in args.matrix.split(",")] if args.matrix else None
    out = pathlib.Path(args.out) if args.out else None
    run_leaderboard(args.corpus, scanners, tier=args.tier, matrix_axes=axes,
                    corpus_root=args.corpus_root, out_dir=out)
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
