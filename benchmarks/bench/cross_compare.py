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
from dataclasses import dataclass

from .report import load_results
from .schema import RunResult

_BENCH_ROOT = pathlib.Path(__file__).resolve().parents[1]
REQUIRED_COMPETITORS = ("betterleaks", "kingfisher")
REQUIRED_KEYHOG_OSES = ("linux", "macos", "windows")


@dataclass(frozen=True)
class DominanceVerdict:
    violations: list[str]
    competitor_best: dict[str, float]
    keyhog_by_os: dict[str, float]

    @property
    def ok(self) -> bool:
        return not self.violations


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


def _os_key(r: RunResult) -> str:
    raw = (r.host.os or "").lower()
    if raw.startswith("darwin") or raw.startswith("mac"):
        return "macos"
    if raw.startswith("win"):
        return "windows"
    if raw.startswith("linux"):
        return "linux"
    return raw or "unknown"


def _speed(r: RunResult) -> float:
    return float(r.speed.throughput_mb_s or 0.0)


def evaluate_dominance(
    rows: list[tuple[str, RunResult]],
    *,
    factor: float = 10.0,
    competitors: tuple[str, ...] = REQUIRED_COMPETITORS,
    required_oses: tuple[str, ...] = REQUIRED_KEYHOG_OSES,
) -> DominanceVerdict:
    """Gate the release contract from cross-device RunResults.

    Contract: for every required OS, keyhog's fastest available row must be at
    least ``factor`` times faster than each named competitor's fastest row on
    any device/OS, while not losing precision, recall, or F1 against that
    competitor's fastest row. Missing keyhog OS rows or missing competitor rows
    are hard violations; absence cannot be counted as evidence.
    """
    violations: list[str] = []
    competitor_rows: dict[str, RunResult] = {}
    keyhog_by_os_rows: dict[str, RunResult] = {}

    for _device, r in rows:
        if not r.available:
            continue
        speed = _speed(r)
        if r.scanner.name in competitors:
            prev = competitor_rows.get(r.scanner.name)
            if prev is None or speed > _speed(prev):
                competitor_rows[r.scanner.name] = r
        elif r.scanner.name == "keyhog":
            os_key = _os_key(r)
            prev = keyhog_by_os_rows.get(os_key)
            if prev is None or speed > _speed(prev):
                keyhog_by_os_rows[os_key] = r

    for name in competitors:
        if name not in competitor_rows:
            violations.append(f"missing required competitor result: {name}")

    for os_key in required_oses:
        if os_key not in keyhog_by_os_rows:
            violations.append(f"missing required keyhog OS result: {os_key}")

    competitor_best = {
        name: _speed(row) for name, row in sorted(competitor_rows.items())
    }
    keyhog_by_os = {
        os_key: _speed(row) for os_key, row in sorted(keyhog_by_os_rows.items())
    }

    for os_key, keyhog in sorted(keyhog_by_os_rows.items()):
        if os_key not in required_oses:
            continue
        ko = keyhog.detection.overall
        for name, competitor in sorted(competitor_rows.items()):
            co = competitor.detection.overall
            required_speed = _speed(competitor) * factor
            actual_speed = _speed(keyhog)
            if actual_speed < required_speed:
                violations.append(
                    f"{os_key}: keyhog {actual_speed:.4f} MB/s < {factor:.1f}x "
                    f"{name} fastest {_speed(competitor):.4f} MB/s"
                )
            if ko.precision() < co.precision():
                violations.append(
                    f"{os_key}: keyhog precision {ko.precision():.4f} < "
                    f"{name} precision {co.precision():.4f}"
                )
            if ko.recall() < co.recall():
                violations.append(
                    f"{os_key}: keyhog recall {ko.recall():.4f} < "
                    f"{name} recall {co.recall():.4f}"
                )
            if ko.f1() < co.f1():
                violations.append(
                    f"{os_key}: keyhog F1 {ko.f1():.4f} < "
                    f"{name} F1 {co.f1():.4f}"
                )

    return DominanceVerdict(
        violations=violations,
        competitor_best=competitor_best,
        keyhog_by_os=keyhog_by_os,
    )


def render_dominance(verdict: DominanceVerdict) -> str:
    lines = ["cross-device dominance gate"]
    if verdict.competitor_best:
        lines.append("competitor fastest paths:")
        for name, speed in verdict.competitor_best.items():
            lines.append(f"  {name}: {speed:.4f} MB/s")
    if verdict.keyhog_by_os:
        lines.append("keyhog fastest path by OS:")
        for os_key, speed in verdict.keyhog_by_os.items():
            lines.append(f"  {os_key}: {speed:.4f} MB/s")
    if verdict.ok:
        lines.append("PASS")
    else:
        lines.append(f"FAIL ({len(verdict.violations)} violation(s))")
        for violation in verdict.violations:
            lines.append(f"  - {violation}")
    return "\n".join(lines)


def _main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Compare per-host bench results across devices.")
    ap.add_argument("--root", type=pathlib.Path,
                    default=_BENCH_ROOT / "results-cross-device")
    ap.add_argument("--corpus", default="mirror")
    ap.add_argument("--scanner", default=None, help="filter to one scanner (e.g. keyhog)")
    ap.add_argument("--dominance-gate", action="store_true",
                    help="fail unless keyhog is 10x faster than BetterLeaks and Kingfisher on every required OS")
    ap.add_argument("--factor", type=float, default=10.0)
    ap.add_argument("--required-oses", default="linux,macos,windows")
    args = ap.parse_args(argv)
    scanner = None if args.dominance_gate else args.scanner
    rows = rows_for(args.root, args.corpus, scanner)
    if args.dominance_gate:
        required_oses = tuple(s.strip().lower() for s in args.required_oses.split(",") if s.strip())
        verdict = evaluate_dominance(rows, factor=args.factor, required_oses=required_oses)
        print(render_dominance(verdict))
        return 0 if verdict.ok else 1
    print(render(rows))
    return 0 if rows else 1


if __name__ == "__main__":
    raise SystemExit(_main())
