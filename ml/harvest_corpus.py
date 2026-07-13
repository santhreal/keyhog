#!/usr/bin/env python3
"""Stage 1 of the ML feedback loop: harvest REAL labeled training examples from
the corpora keyhog is actually deployed against (CredData, homefield), so the
MoE can be trained on the real distribution instead of synthetic data alone.

Why: the model is trained only on `ml/corpus.py`'s synthetic generators and
scores real-but-shape-ambiguous secrets (lowercase-heavy tokens, digit-run ids,
symbol-laden passwords) near ~0.02 because it learned "junk-looking shape =
non-secret" from synthetic negatives. Feeding it the real distribution, the
actual candidates keyhog surfaces, labelled by ground truth, is the
categorical fix.

For each keyhog finding we emit a corpus record
`{text, context, label, kind, class, detector_id}`
matching `ml/corpus.py`'s schema:
  - text    : the finding's credential value (what the model scores)
  - context : the SERVE ml_context: "file:{path}\n{±5-line window}", a
              byte-mirror of `crate::pipeline::local_context_window(.., line, 5)`
              + the `file:` prefix, so train == serve.
  - label   : ground-truth overlap (1 = overlaps a labelled positive secret,
              0 = on a known file overlapping no positive). `ignore`/template
              records are dropped (neither class).
  - kind    : provenance, e.g. `real-creddata-pos` / `real-homefield-neg`.
  - class   : ground-truth secret category used by per-class retrain gates.
  - detector_id: keyhog detector that produced the candidate, used by the
              per-detector model-card breakdown.

Run:
  python3 ml/harvest_corpus.py --corpora creddata homefield \
      --keyhog-bin <path-to-keyhog> --out ml/data/real_corpus.jsonl

The split into train/held-out by file/repo (no leakage) is done downstream in
train_classifier.py; this script only emits labelled records + their on-disk
file so the splitter can group by it.
"""
from __future__ import annotations

import argparse
import dataclasses
import json
import pathlib
import sys
from collections import Counter

HERE = pathlib.Path(__file__).resolve().parent
BENCH = HERE.parent / "benchmarks"
sys.path.insert(0, str(BENCH))

from bench.corpora.base import resolve_corpus  # noqa: E402
from bench.scanners.base import resolve_scanner  # noqa: E402
from bench.score import (  # noqa: E402
    _build_file_index,
    _file_category,
    _resolve_finding_file,
    _resolve_finding_file_candidates,
    overlap,
)

# Mirror of crate::types::ML_CONTEXT_RADIUS_LINES.
ML_CONTEXT_RADIUS_LINES = 5


def serve_context(file_label: str, abs_path: pathlib.Path, line: int) -> str:
    """Reconstruct keyhog's serve ml_context for a finding: byte-mirror of
    `local_context_window(text, line, 5)` (1-based line; an 11-line window
    `\\n`-joined with no trailing newline; empty when the file has fewer lines
    than the window start) prefixed with `file:{path}\\n` exactly as
    `calculate_final_score` builds it."""
    prefix = f"file:{file_label}\n"
    if line <= 0:
        return prefix
    try:
        text = abs_path.read_text(errors="replace")
    except OSError:
        return prefix
    lines = text.split("\n")
    lines_before = max(0, line - ML_CONTEXT_RADIUS_LINES - 1)
    if lines_before >= len(lines):
        return prefix  # window underflow → Rust returns ""
    window = "\n".join(lines[lines_before : lines_before + (2 * ML_CONTEXT_RADIUS_LINES + 1)])
    return prefix + window


UNKNOWN_PROVENANCE_LABELS = {"", "unknown", "none", "null", "n/a", "na"}


def _required_provenance_label(value: object, field: str, context: str) -> str:
    if isinstance(value, str):
        label = value.strip()
        if label and label.lower() not in UNKNOWN_PROVENANCE_LABELS:
            return label
    raise ValueError(
        f"{context}: missing explicit {field}; fix corpus/finding provenance "
        "before harvesting real ML training rows"
    )


def _finding_detector_id(finding: dict, context: str) -> str:
    for field in ("detector", "detector_id"):
        value = finding.get(field)
        if isinstance(value, str):
            label = value.strip()
            if label and label.lower() not in UNKNOWN_PROVENANCE_LABELS:
                return label
    raise ValueError(
        f"{context}: missing explicit detector_id; fix corpus/finding provenance "
        "before harvesting real ML training rows"
    )


def classify_finding(recs, value: str, context: str = "finding") -> tuple[int, str, bool]:
    """Label a candidate and return (label, class, ignored).

    This mirrors the scorer's attribution rule: overlap with a positive record
    is a training positive; overlap with an ignore/template record is dropped;
    anything else on a known file is a negative attributed to that file's
    scorer category.
    """
    matched = [
        r for r in recs
        if r.label and not r.ignore and overlap(value, r.secret)
    ]
    if matched:
        return 1, _required_provenance_label(
            matched[0].category,
            "class",
            f"{context}: positive record {matched[0].id}",
        ), False
    if any(r.ignore and overlap(value, r.secret) for r in recs):
        return 0, "", True
    category = _required_provenance_label(
        _file_category(recs),
        "class",
        f"{context}: false-positive file",
    )
    return 0, category, False


def harvest(corpus_name: str, keyhog_bin: str | None, floor: float) -> list[dict]:
    corpus = resolve_corpus(corpus_name)
    records = corpus.records()
    by_key, aliases = _build_file_index(records, corpus.file_root)

    scanner = resolve_scanner("keyhog", binary=keyhog_bin) if keyhog_bin \
        else resolve_scanner("keyhog")
    if not scanner.available():
        raise SystemExit(f"keyhog binary not found: {scanner.binary}")
    # Harvest at a LOW report floor (not the default ~0.30) so the corpus
    # captures every candidate the pipeline scores, including the sub-floor
    # ones the default floor hides. A retrain that only sees above-floor
    # candidates can never learn the hard negatives keyhog currently fires on
    # but scores below threshold; training on those is what stops a retrained
    # model from over-promoting them (the kubernetes-bootstrap-token +203-FP
    # regression came from exactly that blind spot). The score upstream gates
    # (shape gates, entropy floor) still apply, so this is the full set the MoE
    # is asked to score at serve time, never more.
    cfg = dataclasses.replace(scanner.default_config(), min_confidence=floor)
    findings, _stats = scanner.run(corpus.scan_root, cfg)

    out: list[dict] = []
    skipped_no_record = 0
    skipped_ignore = 0
    for f in findings:
        value = f.get("value") or ""
        if not value:
            continue
        fpath = f.get("file") or ""
        matches = _resolve_finding_file_candidates(fpath, aliases) if fpath else set()
        if len(matches) > 1:
            raise ValueError(
                f"{corpus_name}:{fpath}: ambiguous finding path matched "
                f"{len(matches)} corpus files; emit exact scan paths before "
                "harvesting real ML training rows"
            )
        key = _resolve_finding_file(fpath, aliases) if fpath else None
        if key is None:
            skipped_no_record += 1
            continue  # no ground-truth record on this file → can't label
        recs = by_key[key]
        context = f"{corpus_name}:{fpath or '<missing-file>'}"
        label, secret_class, ignored = classify_finding(recs, value, context)
        if ignored:
            skipped_ignore += 1
            continue  # template/placeholder ground truth → neither class
        line = f.get("line") or 0
        detector_id = _finding_detector_id(f, context)
        out.append(
            {
                "text": value,
                "context": serve_context(fpath, pathlib.Path(key), line),
                "label": label,
                "kind": f"real-{corpus_name}-{'pos' if label else 'neg'}",
                "class": secret_class,
                "detector_id": detector_id,
                # provenance for the no-leakage group split downstream
                "source_file": key,
            }
        )
    print(
        f"[{corpus_name}] findings={len(findings)} emitted={len(out)} "
        f"(pos={sum(r['label'] for r in out)} neg={sum(1 - r['label'] for r in out)}) "
        f"skipped_no_record={skipped_no_record} skipped_ignore={skipped_ignore}",
        file=sys.stderr,
    )
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--corpora", nargs="+", default=["creddata"],
                    help="corpus names to harvest (resolve_corpus)")
    ap.add_argument("--keyhog-bin", default=None,
                    help="keyhog binary (defaults to KEYHOG_BIN env / freshly built)")
    ap.add_argument("--harvest-floor", type=float, default=0.0,
                    help="report-confidence floor for the harvest scan (default "
                         "0.0 = capture every scored candidate, incl. sub-floor "
                         "hard negatives the default ~0.30 floor hides). Upstream "
                         "shape/entropy gates still apply, so this is exactly the "
                         "candidate set the MoE scores at serve time.")
    ap.add_argument("--out", default="ml/data/real_corpus.jsonl")
    args = ap.parse_args()
    if not (0.0 <= args.harvest_floor <= 1.0):
        ap.error(f"--harvest-floor must be in [0.0, 1.0], got {args.harvest_floor}")

    all_rows: list[dict] = []
    failures: list[str] = []
    for name in args.corpora:
        try:
            all_rows.extend(harvest(name, args.keyhog_bin, args.harvest_floor))
        except SystemExit:
            raise
        except Exception as exc:
            failure = f"{name}: {exc}"
            failures.append(failure)
            print(f"[{name}] harvest FAILED: {exc}", file=sys.stderr)

    if failures:
        print(
            "not writing real-corpus output because requested corpus harvest failed: "
            + "; ".join(failures),
            file=sys.stderr,
        )
        return 1

    out_path = pathlib.Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w") as fh:
        for row in all_rows:
            fh.write(json.dumps(row) + "\n")

    kinds = Counter(r["kind"] for r in all_rows)
    files = len({r["source_file"] for r in all_rows})
    print(f"wrote {len(all_rows)} records across {files} files -> {out_path}")
    for k, n in sorted(kinds.items()):
        print(f"  {k}: {n}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
