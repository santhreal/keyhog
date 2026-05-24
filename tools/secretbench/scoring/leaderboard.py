#!/usr/bin/env python3
"""Score every available scanner against a SecretBench-shape corpus
and emit one leaderboard JSON.

This wraps `score.py`'s scoring engine and runs each requested
scanner in turn. Missing binaries are recorded as `available=false`
in the output rather than silently skipped, so a partial leaderboard
is always traceable to a specific missing dependency.

Usage::

    python tools/secretbench/scoring/leaderboard.py \
        --corpus tools/secretbench/mirror/corpus \
        --output tools/secretbench/results/leaderboard.json
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import score  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--corpus", type=pathlib.Path, required=True)
    ap.add_argument("--output", type=pathlib.Path, required=True)
    ap.add_argument(
        "--scanners",
        nargs="+",
        default=list(score.SCANNERS.keys()),
        choices=list(score.SCANNERS.keys()),
        help="Which scanners to score (default: all known)",
    )
    args = ap.parse_args()

    records, root = score.load_corpus(args.corpus)
    print(f"Loaded {len(records)} records", file=sys.stderr)

    leaderboard: dict[str, dict] = {}
    for scanner in args.scanners:
        print(f"\n▶ running {scanner}…", file=sys.stderr)
        report = score.score_corpus(records, root, scanner)
        leaderboard[scanner] = report.to_json()
        if report.available:
            o = report.overall
            print(
                f"  {scanner}: P={o.precision():.4f}  R={o.recall():.4f}  "
                f"F1={o.f1():.4f}  ({report.total_time_ms / 1000:.1f}s, "
                f"{report.finding_count} findings)",
                file=sys.stderr,
            )
        else:
            print(f"  {scanner}: not available — {report.error}", file=sys.stderr)

    # Rank by F1, ignoring unavailable scanners.
    ranked = sorted(
        ((name, r) for name, r in leaderboard.items() if r["available"]),
        key=lambda kv: kv[1]["overall"]["f1"],
        reverse=True,
    )
    rank_summary = [
        {
            "rank": i + 1,
            "scanner": name,
            "f1": r["overall"]["f1"],
            "precision": r["overall"]["precision"],
            "recall": r["overall"]["recall"],
            "total_time_ms": r["total_time_ms"],
        }
        for i, (name, r) in enumerate(ranked)
    ]

    payload = {
        "generated_at": _dt.datetime.now(_dt.timezone.utc).isoformat(),
        "corpus": str(args.corpus),
        "fixture_count": len(records),
        "ranking": rank_summary,
        "scanners": leaderboard,
        "citation": (
            "If reporting numbers from the real SecretBench dataset (not "
            "the mirror corpus), cite: Basak, S. K., Neil, L., Reaves, B., "
            "Williams, L. (2023). SecretBench: A Dataset of Software "
            "Secrets. MSR. arXiv:2303.06729."
        ),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2))

    print(f"\nleaderboard:", file=sys.stderr)
    for entry in rank_summary:
        print(
            f"  {entry['rank']}.  {entry['scanner']:<14} "
            f"F1 {entry['f1']:.4f}  P {entry['precision']:.4f}  "
            f"R {entry['recall']:.4f}  ({entry['total_time_ms'] / 1000:.1f}s)",
            file=sys.stderr,
        )
    print(f"\nwrote {args.output}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
