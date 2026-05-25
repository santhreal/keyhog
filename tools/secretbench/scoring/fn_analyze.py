#!/usr/bin/env python3
"""Diagnose false negatives: which truth records did the scanner miss?

Mirror of fp_analyze.py but for misses. Buckets every label=true
fixture that was NOT overlapped by any finding, grouped by
(category, wrapper-comment), with examples so the engineer can
see exact secret shape + file context.
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
    ap.add_argument("--output", type=pathlib.Path, default=None)
    ap.add_argument("--max-examples", type=int, default=5)
    ap.add_argument("--only-category", default=None,
                    help="Only show this category (e.g. cloud-service-credential)")
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

    # Build hit set: which record_ids have any overlapping finding?
    hit_ids: set[str] = set()
    for f in findings:
        rec = rec_by_path.get(f["file"])
        if rec is None:
            for k, v in rec_by_path.items():
                if k.endswith(f["file"]) or f["file"].endswith(k.rsplit("/", 1)[-1]):
                    rec = v
                    break
        if rec is None:
            continue
        if rec.get("label") and score.overlap(f["value"], rec["secret"]):
            hit_ids.add(rec["id"])

    # Bucket every FN by (category, wrapper-comment).
    fn_buckets: dict[tuple[str, str], list[dict]] = defaultdict(list)
    fn_count_by_category: Counter[str] = Counter()
    fn_count_by_wrapper: Counter[str] = Counter()
    fn_count_by_cat_wrapper: Counter[tuple[str, str]] = Counter()

    for rec in records:
        if not rec.get("label"):
            continue
        if rec["id"] in hit_ids:
            continue
        cat = rec.get("category", "?")
        if args.only_category and cat != args.only_category:
            continue
        # Comment is the wrapper signal in the mirror manifest, e.g.
        # `wrapper=shell-export`, `wrapper=ts-decorator`.
        comment = rec.get("comment", "?")
        wrapper = comment.replace("wrapper=", "") if comment.startswith("wrapper=") else comment
        fn_buckets[(cat, wrapper)].append(rec)
        fn_count_by_category[cat] += 1
        fn_count_by_wrapper[wrapper] += 1
        fn_count_by_cat_wrapper[(cat, wrapper)] += 1

    total_fn = sum(fn_count_by_category.values())

    out: list[str] = []
    out.append(f"FN analysis for {args.scanner} on {args.corpus} ({len(records)} fixtures)")
    out.append(f"Total FNs (filtered): {total_fn}")
    out.append("")
    out.append("─── FN counts by category ───")
    for cat, n in fn_count_by_category.most_common():
        out.append(f"  {n:>5}  {cat}")
    out.append("")
    out.append("─── FN counts by wrapper ───")
    for wrap, n in fn_count_by_wrapper.most_common(30):
        out.append(f"  {n:>5}  {wrap}")
    out.append("")
    out.append("─── Top (category × wrapper) cells (most missed shapes) ───")
    for (cat, wrap), n in fn_count_by_cat_wrapper.most_common(40):
        out.append(f"  {n:>5}  [{cat}] × [{wrap}]")
    out.append("")
    out.append("─── Examples per cell ───")
    for (cat, wrap), recs in sorted(fn_buckets.items(), key=lambda kv: -len(kv[1])):
        out.append(f"\n[{cat}] × [{wrap}]  ({len(recs)} FNs, showing first {args.max_examples})")
        for rec in recs[: args.max_examples]:
            secret = rec.get("secret", "")
            redacted = secret[:30] + "…" if len(secret) > 30 else secret
            path = root / rec.get("on_disk_path", rec.get("file_path", ""))
            out.append(f"  - secret={redacted!r:<35} file={path.name} line={rec.get('start_line','?')}")
            try:
                content = path.read_text(errors="replace").splitlines()
                start = max(0, rec.get("start_line", 1) - 2)
                end = min(len(content), rec.get("end_line", rec.get("start_line", 1)) + 1)
                for i in range(start, end):
                    out.append(f"      {i+1:>4}| {content[i][:120]}")
            except Exception as exc:
                out.append(f"      <unreadable: {exc}>")

    text = "\n".join(out)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text + "\n")
        print(f"wrote {args.output}", file=sys.stderr)
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
