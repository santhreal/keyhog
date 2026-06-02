"""Cross-device comparison: one row per (device, scanner) from the per-host
RunResults that cross_device.sh pulls into ``results-cross-device/<device>/``.

This is deliberately SEPARATE from the README leaderboard (bench.report): that
report ranks scanners on ONE reference host, whereas this ranks the SAME
scanner across machines/OSes so a per-OS detection or speed delta (e.g. the
vyre CPU path on macOS vs Hyperscan SIMD on Linux) is visible at a glance.
Keeping it out of ``results/`` is what stops a remote host's row from shadowing
the canonical numbers in ``canonical_leaderboard``.
"""

from __future__ import annotations

import argparse
import pathlib
import sys

from .report import load_results

_BENCH_ROOT = pathlib.Path(__file__).resolve().parents[1]


def rows_for(root: pathlib.Path, corpus: str, scanner: str | None):
    """(device, RunResult) for every available run of ``corpus`` under each
    ``<device>/`` subdir, optionally filtered to one scanner."""
    out = []
    if not root.is_dir():
        return out
    for dev_dir in sorted(p for p in root.iterdir() if p.is_dir()):
        for r in load_results(dev_dir):
            if r.corpus.name != corpus or not r.available:
                continue
            if scanner and r.scanner.name != scanner:
                continue
            out.append((dev_dir.name, r))
    return out


def render(rows) -> str:
    if not rows:
        return "_No cross-device results yet — run benchmarks/cross_device.sh._"
    lines = [
        "| Device | OS / arch | Scanner | F1 | Precision | Recall | Wall | Peak RSS |",
        "|---|---|---|---|---|---|---|---|",
    ]
    # Highest F1 first so the strongest host reads at the top.
    for device, r in sorted(rows, key=lambda t: t[1].detection.overall.f1(), reverse=True):
        o = r.detection.overall
        osarch = f"{r.host.os or '?'} {r.host.cpu or ''}".strip()
        wall = f"{r.speed.wall_ms / 1000:.2f}s" if r.speed.wall_ms else "-"
        rss = f"{r.speed.peak_rss_kb // 1024} MB" if r.speed.peak_rss_kb else "-"
        lines.append(
            f"| {device} | {osarch} | {r.scanner.name} | {o.f1():.4f} | "
            f"{o.precision():.4f} | {o.recall():.4f} | {wall} | {rss} |"
        )
    return "\n".join(lines)


def _main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Compare per-host bench results across devices.")
    ap.add_argument("--root", type=pathlib.Path,
                    default=_BENCH_ROOT / "results-cross-device")
    ap.add_argument("--corpus", default="mirror")
    ap.add_argument("--scanner", default=None, help="filter to one scanner (e.g. keyhog)")
    args = ap.parse_args(argv)
    rows = rows_for(args.root, args.corpus, args.scanner)
    print(render(rows))
    return 0 if rows else 1


if __name__ == "__main__":
    raise SystemExit(_main())
