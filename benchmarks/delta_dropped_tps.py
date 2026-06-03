#!/usr/bin/env python3
"""Identify the entropy-unification's dropped TPs: secrets the baseline
(e6cb66b1) caught but the entropy->MoE build misses. Inspect their shape so we
know whether a cheap non-model recall floor (entropy magnitude / charset /
length / prefix) can separate them from the suppressed FPs.
"""
import math
import os
import pathlib
import sys

from bench.corpora.base import resolve_corpus
from bench.scanners.base import resolve_scanner
from bench.score import _build_file_index, _resolve_finding_file, overlap

BASE = "/mnt/FlareTraining/santh-archive/cargo-target/keyhog-baseline/release-fast/keyhog"
NEW = "/mnt/FlareTraining/santh-archive/cargo-target/keyhog/release-fast/keyhog"


def shannon(s: str) -> float:
    if not s:
        return 0.0
    from collections import Counter
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in Counter(s).values())


def hits(corpus, findings):
    """record.id -> (value, detector, confidence) of a finding that caught it."""
    records = corpus.records()
    by_key, aliases = _build_file_index(records, corpus.file_root)
    caught = {}
    for f in findings:
        fpath = f.get("file") or ""
        key = _resolve_finding_file(fpath, aliases) if fpath else None
        if key is None:
            continue
        value = f.get("value") or ""
        for rec in by_key[key]:
            if rec.label and not rec.ignore and overlap(value, rec.secret):
                # keep the highest-confidence finding per record
                prev = caught.get(rec.id)
                conf = f.get("confidence") or 0.0
                if prev is None or conf > prev[2]:
                    caught[rec.id] = (value, f.get("detector") or "?", conf)
    return caught


def main():
    corpus = resolve_corpus("creddata")
    cfg_scanner = resolve_scanner("keyhog", binary=BASE)
    base_findings, _ = cfg_scanner.run(corpus.scan_root, cfg_scanner.default_config())
    base_hits = hits(corpus, base_findings)

    new_scanner = resolve_scanner("keyhog", binary=NEW)
    new_findings, _ = new_scanner.run(corpus.scan_root, new_scanner.default_config())
    new_hits = hits(corpus, new_findings)

    dropped = set(base_hits) - set(new_hits)
    print(f"baseline TPs={len(base_hits)}  new TPs={len(new_hits)}  dropped={len(dropped)}\n")
    print(f"{'detector':<22}{'baseConf':>9}{'len':>5}{'entropy':>9}  value")
    by_det = {}
    for rid in sorted(dropped):
        value, det, conf = base_hits[rid]
        by_det[det] = by_det.get(det, 0) + 1
        ent = shannon(value)
        shown = value if len(value) <= 44 else value[:41] + "..."
        print(f"{det:<22}{conf:>9.3f}{len(value):>5}{ent:>9.3f}  {shown!r}")
    print("\nby detector:", dict(sorted(by_det.items(), key=lambda kv: -kv[1])))
    # How many dropped TPs were ENTROPY-path (the only path the change touches)?
    ent_dropped = sum(1 for rid in dropped if base_hits[rid][1].startswith("entropy-"))
    print(f"entropy-* among dropped: {ent_dropped} / {len(dropped)}")


if __name__ == "__main__":
    sys.exit(main())
