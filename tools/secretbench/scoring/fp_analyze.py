#!/usr/bin/env python3
"""Diagnose false positives from a scoreboard run.

Takes a SecretBench-shape corpus + a scanner name, runs the scanner,
and for every FP shows (detector, value seen, fixture category,
fixture file, line, full file contents truncated). This is the
diagnostic loop for going from "FP rate is too high" to "exactly
which detector fires on which shape, fix that one".

Usage::

    python tools/secretbench/scoring/fp_analyze.py \
        --corpus tools/secretbench/mirror/corpus \
        --scanner keyhog \
        --output fp-report.txt
"""

from __future__ import annotations

import argparse
import pathlib
import sys
from collections import Counter, defaultdict

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import score  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--corpus", type=pathlib.Path, required=True)
    ap.add_argument("--scanner", choices=list(score.SCANNERS), required=True)
    ap.add_argument("--output", type=pathlib.Path, default=None,
                    help="Write report to file (default: stdout)")
    ap.add_argument("--max-examples", type=int, default=10,
                    help="Show up to N example FPs per detector × category cell")
    args = ap.parse_args()

    records, root = score.load_corpus(args.corpus)
    print(f"Loaded {len(records)} records", file=sys.stderr)

    file_paths = [score.record_file_path(r, root) for r in records]
    rec_by_path: dict[str, dict] = {}
    for rec, p in zip(records, file_paths):
        rec_by_path[str(p.resolve())] = rec
        rec_by_path[str(p)] = rec

    runner = score.SCANNERS[args.scanner]
    findings = runner(file_paths)
    print(f"{args.scanner} produced {len(findings)} findings", file=sys.stderr)

    # Bucket every FINDING by (detector, fixture-category).
    fp_buckets: dict[tuple[str, str], list[dict]] = defaultdict(list)
    fp_count_by_detector: Counter[str] = Counter()
    fp_count_by_category: Counter[str] = Counter()

    for f in findings:
        rec = rec_by_path.get(f["file"])
        if rec is None:
            for k, v in rec_by_path.items():
                if k.endswith(f["file"]) or f["file"].endswith(k.rsplit("/", 1)[-1]):
                    rec = v
                    break
        if rec is None:
            continue
        # Same overlap rule as score.py
        if rec.get("label") and score.overlap(f["value"], rec["secret"]):
            continue
        # FP path: either label=false fixture OR label=true but no overlap
        det = f.get("detector", "?")
        cat = rec.get("category", "?")
        fp_buckets[(det, cat)].append({
            "file": f["file"],
            "value": f["value"],
            "rec_id": rec.get("id", "?"),
            "rec_secret_redacted": rec.get("secret", "?")[:20] + "…",
        })
        fp_count_by_detector[det] += 1
        fp_count_by_category[cat] += 1

    out_lines: list[str] = []
    total_fp = sum(fp_count_by_detector.values())
    out_lines.append(
        f"FP analysis for {args.scanner} on {args.corpus} ({len(records)} fixtures)"
    )
    out_lines.append(f"Total FPs: {total_fp}")
    out_lines.append("")
    out_lines.append("─── Top detectors by FP count ───")
    for det, n in fp_count_by_detector.most_common(20):
        pct = 100 * n / total_fp if total_fp else 0
        out_lines.append(f"  {n:>5}  ({pct:5.1f}%)  {det}")
    out_lines.append("")
    out_lines.append("─── Top fixture categories by FP count ───")
    for cat, n in fp_count_by_category.most_common(20):
        pct = 100 * n / total_fp if total_fp else 0
        out_lines.append(f"  {n:>5}  ({pct:5.1f}%)  {cat}")
    out_lines.append("")
    out_lines.append("─── Per (detector × category) cells with examples ───")
    cells = sorted(fp_buckets.items(), key=lambda kv: -len(kv[1]))
    for (det, cat), items in cells:
        out_lines.append(
            f"\n[{det}] × [{cat}]  ({len(items)} FPs, showing first {args.max_examples})"
        )
        for i, item in enumerate(items[: args.max_examples]):
            out_lines.append(
                f"  - cred={item['value']!r}  file={item['file']}  "
                f"truth_id={item['rec_id']}"
            )

    text = "\n".join(out_lines)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text + "\n")
        print(f"wrote {args.output}", file=sys.stderr)
    else:
        print(text)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
