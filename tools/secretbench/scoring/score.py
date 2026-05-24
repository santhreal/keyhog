#!/usr/bin/env python3
"""Score one scanner against a SecretBench-shape corpus.

Reads `manifest.jsonl` (mirror corpus) OR `manifest.parquet` /
`*.parquet` / `*.csv` (real SecretBench export) and the on-disk
fixture files, runs the requested scanner over every file, and
attributes findings using the SecretBench truth rules:

* **True positive** — finding's surfaced credential value contains,
  or is contained in, the labeled secret on a `label=true` fixture.
* **False positive** — finding fires on a `label=false` fixture,
  OR fires on a `label=true` fixture but doesn't overlap the
  labeled secret.
* **False negative** — a `label=true` fixture has no finding whose
  surfaced value overlaps the labeled secret.

Emits one JSON with overall + per-category precision/recall/F1, plus
timing.

Usage::

    python tools/secretbench/scoring/score.py \
        --corpus tools/secretbench/mirror/corpus \
        --scanner keyhog \
        --output keyhog-mirror.json
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import pathlib
import shutil
import subprocess
import sys
import time
from collections import defaultdict
from dataclasses import dataclass, field


@dataclass
class Outcome:
    tp: int = 0
    fp: int = 0
    fn: int = 0

    def precision(self) -> float:
        d = self.tp + self.fp
        return self.tp / d if d else 0.0

    def recall(self) -> float:
        d = self.tp + self.fn
        return self.tp / d if d else 0.0

    def f1(self) -> float:
        p = self.precision()
        r = self.recall()
        return 2 * p * r / (p + r) if (p + r) else 0.0


@dataclass
class ScoreReport:
    scanner: str
    version: str = ""
    available: bool = True
    error: str = ""
    overall: Outcome = field(default_factory=Outcome)
    per_category: dict[str, Outcome] = field(default_factory=lambda: defaultdict(Outcome))
    finding_count: int = 0
    total_time_ms: float = 0.0
    fixture_count: int = 0

    def to_json(self) -> dict:
        return {
            "scanner": self.scanner,
            "available": self.available,
            "version": self.version,
            "error": self.error,
            "fixture_count": self.fixture_count,
            "finding_count": self.finding_count,
            "total_time_ms": round(self.total_time_ms, 2),
            "overall": {
                "tp": self.overall.tp,
                "fp": self.overall.fp,
                "fn": self.overall.fn,
                "precision": round(self.overall.precision(), 4),
                "recall": round(self.overall.recall(), 4),
                "f1": round(self.overall.f1(), 4),
            },
            "per_category": {
                cat: {
                    "tp": o.tp,
                    "fp": o.fp,
                    "fn": o.fn,
                    "precision": round(o.precision(), 4),
                    "recall": round(o.recall(), 4),
                    "f1": round(o.f1(), 4),
                }
                for cat, o in sorted(self.per_category.items())
            },
        }


# ── corpus loading ────────────────────────────────────────────────


def load_manifest_jsonl(path: pathlib.Path) -> list[dict]:
    out = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out


def load_manifest_parquet(path: pathlib.Path) -> list[dict]:
    try:
        import pyarrow.parquet as pq
    except ImportError as exc:
        raise SystemExit(
            "parquet input requires `pip install pyarrow` — install or "
            "use --manifest .jsonl"
        ) from exc
    table = pq.read_table(path)
    return [
        {col: table[col][i].as_py() for col in table.column_names}
        for i in range(table.num_rows)
    ]


def load_manifest_csv(path: pathlib.Path) -> list[dict]:
    import csv
    out = []
    with open(path) as f:
        reader = csv.DictReader(f)
        for row in reader:
            # Coerce common typed columns
            for k in ("start_line", "end_line", "start_column", "end_column", "length"):
                if k in row and row[k] != "":
                    row[k] = int(row[k])
            for k in ("label", "has_words", "is_template", "is_multiline", "in_url"):
                if k in row and isinstance(row[k], str):
                    row[k] = row[k].strip().lower() in {"true", "1", "yes", "t"}
            if "entropy" in row and row["entropy"] != "":
                row["entropy"] = float(row["entropy"])
            out.append(row)
    return out


def load_corpus(corpus: pathlib.Path) -> tuple[list[dict], pathlib.Path]:
    """Return (records, file_root). file_root is the prefix under
    which `on_disk_path` (or `file_path`) values resolve."""
    if corpus.is_file():
        # Single manifest file; on_disk_path is relative to corpus.parent
        if corpus.suffix == ".jsonl":
            return load_manifest_jsonl(corpus), corpus.parent
        if corpus.suffix == ".parquet":
            return load_manifest_parquet(corpus), corpus.parent
        if corpus.suffix == ".csv":
            return load_manifest_csv(corpus), corpus.parent
        raise SystemExit(f"unrecognised manifest format: {corpus}")
    # Directory: look for manifest.jsonl OR a *.parquet inside.
    jl = corpus / "manifest.jsonl"
    if jl.exists():
        return load_manifest_jsonl(jl), corpus
    parquets = sorted(corpus.glob("*.parquet"))
    if parquets:
        recs = []
        for p in parquets:
            recs.extend(load_manifest_parquet(p))
        return recs, corpus
    csvs = sorted(corpus.glob("*.csv"))
    if csvs:
        recs = []
        for c in csvs:
            recs.extend(load_manifest_csv(c))
        return recs, corpus
    raise SystemExit(f"no manifest.jsonl or *.parquet/*.csv in {corpus}")


def record_file_path(rec: dict, root: pathlib.Path) -> pathlib.Path:
    p = rec.get("on_disk_path") or rec.get("file_path")
    return root / p


# ── scanner adapters ──────────────────────────────────────────────


def run_keyhog(file_paths: list[pathlib.Path], binary: str = "keyhog") -> list[dict]:
    """Run keyhog over the given files. Returns a list of finding
    dicts each with at least {"file": str, "value": str}."""
    if shutil.which(binary) is None:
        raise FileNotFoundError(f"keyhog binary not found on PATH: {binary}")
    # `keyhog scan` accepts ONE PATH argument (file or directory),
    # not a list. Batch by parent dir so a 100k-fixture sharded
    # corpus pays one keyhog cold-start (~250 ms) per shard (256
    # shards) instead of per file (100k × cold-start). The
    # `--format json --show-secrets --no-suppress-test-fixtures`
    # combination is what makes scoring apples-to-apples with
    # trufflehog/gitleaks (which don't suppress demo tokens).
    norm: list[dict] = []
    parents = sorted({fp.parent for fp in file_paths})
    for parent in parents:
        cmd = [
            binary, "scan", "--format", "json", "--show-secrets",
            "--no-suppress-test-fixtures",
            str(parent),
        ]
        completed = subprocess.run(
            cmd, capture_output=True, text=True, check=False, timeout=1800,
        )
        out = completed.stdout.strip()
        if not out:
            continue
        try:
            data = json.loads(out)
        except json.JSONDecodeError:
            continue
        # keyhog emits a JSON ARRAY of finding objects. Each shape:
        # {detector_id, detector_name, service, severity,
        # credential_redacted (NB: contains full secret when
        # --show-secrets is set), credential_hash, location:
        # {file_path, line, offset, source}, confidence,
        # verification, ...}.
        findings = data if isinstance(data, list) else (data.get("findings") or [])
        for f in findings:
            loc = f.get("location", {}) or {}
            value = (
                f.get("credential_redacted")
                or f.get("credential")
                or ""
            )
            norm.append({
                "file": loc.get("file_path") or loc.get("file") or "",
                "line": loc.get("line", 0),
                "value": value,
                "detector": f.get("detector_id") or f.get("detector_name") or "",
            })
    return norm


def run_trufflehog(file_paths: list[pathlib.Path], binary: str = "trufflehog") -> list[dict]:
    if shutil.which(binary) is None:
        raise FileNotFoundError(f"trufflehog binary not found on PATH: {binary}")
    # trufflehog filesystem mode emits one JSON-per-line to stdout.
    # Batch by parent directory so a 100k-fixture corpus pays one
    # trufflehog cold-start per shard (~256 dirs) instead of per file
    # (~100k cold-starts at ~300 ms each = 8 hours of pure spawn cost).
    norm: list[dict] = []
    parents = sorted({fp.parent for fp in file_paths})
    for parent in parents:
        cmd = [binary, "filesystem", "--json", "--no-verification", str(parent)]
        completed = subprocess.run(
            cmd, capture_output=True, text=True, check=False, timeout=1800,
        )
        for line in completed.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                f = json.loads(line)
            except json.JSONDecodeError:
                continue
            value = f.get("Raw") or f.get("Redacted") or ""
            src = f.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {}) or {}
            norm.append({
                "file": src.get("file", str(parent)),
                "line": src.get("line", 0),
                "value": value,
                "detector": f.get("DetectorName", ""),
            })
    return norm


def run_gitleaks(file_paths: list[pathlib.Path], binary: str = "gitleaks") -> list[dict]:
    if shutil.which(binary) is None:
        raise FileNotFoundError(f"gitleaks binary not found on PATH: {binary}")
    # gitleaks `detect --source DIR --no-git` is the filesystem mode.
    norm: list[dict] = []
    parents = sorted({fp.parent for fp in file_paths})
    for parent in parents:
        with subprocess.Popen(
            [
                binary, "detect", "--source", str(parent), "--no-git",
                "--report-format", "json", "--report-path", "/dev/stdout",
                "--exit-code", "0",
            ],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
        ) as proc:
            out, _ = proc.communicate(timeout=600)
        try:
            data = json.loads(out) if out.strip() else []
        except json.JSONDecodeError:
            data = []
        for f in data:
            norm.append({
                "file": f.get("File", ""),
                "line": f.get("StartLine", 0),
                "value": f.get("Secret") or f.get("Match") or "",
                "detector": f.get("RuleID", ""),
            })
    return norm


SCANNERS = {
    "keyhog": run_keyhog,
    "trufflehog": run_trufflehog,
    "gitleaks": run_gitleaks,
}


# ── attribution ───────────────────────────────────────────────────


def overlap(a: str, b: str) -> bool:
    """SecretBench paper's containment rule: either side contains
    the other. Keeps the metric robust to scanner-specific
    redaction (e.g. `**...XX` partial-redact), token re-wrapping
    (e.g. trufflehog adding `Bearer ` to OAuth tokens), and the
    common case where one scanner reports just the secret body
    while another reports key=value together."""
    if not a or not b:
        return False
    return a in b or b in a


def score_corpus(
    records: list[dict],
    file_root: pathlib.Path,
    scanner: str,
) -> ScoreReport:
    if scanner not in SCANNERS:
        return ScoreReport(scanner=scanner, available=False,
                           error=f"unknown scanner {scanner!r}")

    file_paths = [record_file_path(r, file_root) for r in records]
    # Index records by absolute path for finding -> truth lookup
    rec_by_path: dict[str, dict] = {}
    for rec, path in zip(records, file_paths):
        rec_by_path[str(path.resolve())] = rec
        rec_by_path[str(path)] = rec  # also non-resolved
        rec_by_path[rec.get("on_disk_path", "")] = rec

    report = ScoreReport(scanner=scanner, fixture_count=len(records))
    t0 = time.perf_counter()
    try:
        findings = SCANNERS[scanner](file_paths)
    except FileNotFoundError as exc:
        report.available = False
        report.error = str(exc)
        return report
    t1 = time.perf_counter()
    report.total_time_ms = (t1 - t0) * 1000.0
    report.finding_count = len(findings)

    # For each fixture: track whether ANY finding overlapped its
    # labeled secret (for TP/FN), and accumulate FPs from
    # non-overlapping findings.
    hit_record_ids: set[str] = set()
    fp_findings = 0

    for f in findings:
        fpath = f["file"]
        rec = rec_by_path.get(fpath)
        if rec is None:
            # Try path tail match
            for k, v in rec_by_path.items():
                if k.endswith(fpath) or fpath.endswith(k.rsplit("/", 1)[-1]):
                    rec = v
                    fpath = k
                    break
        if rec is None:
            fp_findings += 1
            continue
        if rec.get("label") and overlap(f["value"], rec["secret"]):
            hit_record_ids.add(rec["id"])
        else:
            # finding on label=false fixture, OR finding on
            # label=true fixture but on a value that doesn't overlap
            # the labeled secret.
            fp_findings += 1
            cat = rec.get("category", "unknown")
            report.per_category[cat].fp += 1

    for rec in records:
        cat = rec.get("category", "unknown")
        if rec.get("label"):
            if rec["id"] in hit_record_ids:
                report.overall.tp += 1
                report.per_category[cat].tp += 1
            else:
                report.overall.fn += 1
                report.per_category[cat].fn += 1

    report.overall.fp = fp_findings
    return report


# ── main ──────────────────────────────────────────────────────────


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--corpus", type=pathlib.Path, required=True,
                    help="Corpus dir or manifest file (.jsonl/.parquet/.csv)")
    ap.add_argument("--scanner", choices=list(SCANNERS), required=True,
                    help="Which scanner to score")
    ap.add_argument("--output", type=pathlib.Path, required=True,
                    help="Output JSON report path")
    args = ap.parse_args()

    records, root = load_corpus(args.corpus)
    print(f"Loaded {len(records)} records from {args.corpus}", file=sys.stderr)
    report = score_corpus(records, root, args.scanner)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "generated_at": _dt.datetime.now(_dt.timezone.utc).isoformat(),
        "corpus": str(args.corpus),
        "scanner": args.scanner,
        "report": report.to_json(),
    }
    args.output.write_text(json.dumps(payload, indent=2))
    print(f"wrote {args.output}", file=sys.stderr)
    o = report.overall
    print(
        f"\n{args.scanner}: overall P={o.precision():.4f} R={o.recall():.4f} "
        f"F1={o.f1():.4f}  (TP={o.tp} FP={o.fp} FN={o.fn})",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
