"""FP / FN example mining for the benchmark scorer.

:mod:`bench.score` answers *how many* TP/FP/FN per category; this answers
*which ones*, by re-running a scanner and replaying the same attribution to
collect the actual missed positives (FN) and false-firing findings (FP) with
their values, files, and detectors. That's what the detector-tuning loop
needs: the gaps table says "generic-high-entropy-string is the loss", this
dumps the 129 tokens behind it so a rule can be written against real misses,
not guesses.

Consolidates the legacy ``fp_analyze.py`` + ``fn_analyze.py`` into one
package entrypoint that uses the same corpus adapters, scanner adapters, and
overlap rule as the leaderboard, so an "analyze" and a "score" of the same
run never disagree.
"""

from __future__ import annotations

import argparse
import collections
import pathlib
import sys

from .corpora.base import LabeledRecord
from .runner import resolve_corpus_with_root
from .scanners import resolve_scanner
from .score import (
    _build_file_index,
    _resolve_finding_file,
    build_basename_index,
    found_record_ids,
    overlap,
)


def analyze(scanner_name: str, corpus_name: str, *,
            corpus_root: str | pathlib.Path | None = None,
            scanner_binary: str | None = None) -> dict:
    """Run ``scanner_name`` on ``corpus_name`` and return
    ``{"fn": {cat: [records]}, "fp": {cat: [findings]}}``: the unmatched
    positives and the false-firing findings, grouped by category."""
    corpus = resolve_corpus_with_root(corpus_name, corpus_root)
    records = corpus.records()
    if not records:
        raise SystemExit(f"corpus {corpus_name!r} is unlabeled — nothing to analyze")
    scanner = resolve_scanner(scanner_name, binary=scanner_binary)
    if not scanner.available():
        raise SystemExit(f"{scanner_name} binary not found: {scanner.binary}")
    findings, _stats = scanner.run(corpus.scan_root, scanner.default_config())

    by_key, aliases = _build_file_index(records, corpus.file_root)
    basename_index = build_basename_index(aliases)
    # The recall hit-set is score's own attribution — reuse it verbatim so an
    # analyze and a score of the same run can never disagree (they share one
    # overlap/index rule). Only the FP *mining* below is analyze-specific.
    hit_ids = found_record_ids(records, findings, corpus.file_root)
    fp_by_cat: dict[str, list[dict]] = collections.defaultdict(list)

    for f in findings:
        fpath = f.get("file") or ""
        key = _resolve_finding_file(fpath, aliases, basename_index) if fpath else None
        if key is None:
            fp_by_cat["unknown"].append(f)
            continue
        recs = by_key[key]
        value = f.get("value") or ""
        if any(r.label and not r.ignore and overlap(value, r.secret) for r in recs):
            continue
        if any(r.ignore and overlap(value, r.secret) for r in recs):
            continue
        cat = next((r.category for r in recs if r.label and not r.ignore),
                   recs[0].category if recs else "unknown")
        fp_by_cat[cat or "unknown"].append(f)

    fn_by_cat: dict[str, list[LabeledRecord]] = collections.defaultdict(list)
    for r in records:
        if r.label and not r.ignore and r.id not in hit_ids:
            fn_by_cat[r.category or "unknown"].append(r)

    return {"fn": dict(fn_by_cat), "fp": dict(fp_by_cat)}


def print_report(report: dict, top: int) -> None:
    fn, fp = report["fn"], report["fp"]
    print("\n=== FALSE NEGATIVES (missed positives) by category ===")
    for cat in sorted(fn, key=lambda c: -len(fn[c])):
        recs = fn[cat]
        print(f"\n  {cat}: {len(recs)} missed")
        for r in recs[:top]:
            secret = r.secret if len(r.secret) <= 60 else r.secret[:57] + "..."
            print(f"    - {r.file_path}  {secret!r}")
    print("\n=== FALSE POSITIVES (false fires) by category ===")
    for cat in sorted(fp, key=lambda c: -len(fp[c])):
        items = fp[cat]
        print(f"\n  {cat}: {len(items)} false fires")
        for f in items[:top]:
            val = (f.get("value") or "")[:60]
            print(f"    - {f.get('file','?')}  [{f.get('detector','?')}]  {val!r}")


def _main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Mine FP/FN examples for a scanner+corpus.")
    ap.add_argument("--scanner", default="keyhog")
    ap.add_argument("--corpus", default="mirror")
    ap.add_argument("--corpus-root", default=None)
    ap.add_argument("--top", type=int, default=15, help="examples per category")
    args = ap.parse_args(argv)
    report = analyze(args.scanner, args.corpus, corpus_root=args.corpus_root)
    n_fn = sum(len(v) for v in report["fn"].values())
    n_fp = sum(len(v) for v in report["fp"].values())
    print(f"{args.scanner} on {args.corpus}: {n_fn} missed positives, "
          f"{n_fp} false fires", file=sys.stderr)
    print_report(report, args.top)
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
