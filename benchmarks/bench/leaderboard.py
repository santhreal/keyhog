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
* ``perf``  - keyhog's full backend x cache x daemon x mode matrix on one corpus,
  for the speed/RSS table (detection still scored if the corpus is labeled).
"""

from __future__ import annotations

import argparse
import pathlib
import sys

from . import hardware
from .runner import build_result, resolve_corpus_with_root, write_result
from .scanners import resolve_scanner
from .scanners.keyhog import KeyhogScanner
from .schema import RunResult, ScannerConfig

_DEFAULT_SCANNERS = ["keyhog", "betterleaks", "kingfisher", "noseyparker", "trufflehog", "titus"]


def results_dir(base: pathlib.Path | None = None) -> pathlib.Path:
    base = base or (pathlib.Path(__file__).resolve().parents[1] / "results")
    return base / hardware.capture().hostname_hash


def _configs_for(scanner_name: str, tier: str, matrix_axes: list[str] | None) -> list[ScannerConfig]:
    sc = resolve_scanner(scanner_name)
    if scanner_name == "keyhog" and tier == "perf":
        assert isinstance(sc, KeyhogScanner)
        return sc.matrix(matrix_axes or ["backend", "cache", "daemon", "mode"])
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
    version = scanner.version()
    if not scanner.available():
        from .runner import _unavailable_result
        return _unavailable_result(scanner, version, cfg, corpus, "scanner binary not found")
    try:
        findings, stats = scanner.run(corpus.scan_root, cfg)
    except Exception as exc:  # noqa: BLE001 - record, never abort the matrix
        from .runner import _unavailable_result
        return _unavailable_result(scanner, version, cfg, corpus,
                                   f"{type(exc).__name__}: {exc}")
    result = build_result(scanner_name=scanner.name, scanner_version=version,
                          cfg=cfg, corpus=corpus, findings=findings, stats=stats)
    if stats.timed_out:
        result.error = "scanner timed out"
    elif not scanner.exit_success(stats.exit_code):
        result.error = f"scanner exited {stats.exit_code}"
    return result


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
        for cfg in _configs_for(scanner_name, tier, matrix_axes):
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
