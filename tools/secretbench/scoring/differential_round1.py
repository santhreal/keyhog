#!/usr/bin/env python3
"""Round 1 differential: keyhog vs trufflehog vs gitleaks on a
50-fixture random sample of the mirror manifest.

For each fixture-x-scanner cell, we record:
  detected  : did the scanner emit any finding on that fixture file
              whose value overlapped the labeled secret on label=true,
              OR any finding at all on label=false?
  attributed: TP / FP / TN / FN
  per-scanner raw findings on the file (value + detector id)

A disagreement is any fixture where the three scanners do not return
the same {TP, FP, TN, FN} verdict. The "right" verdict per fixture
comes from the manifest label: label=true => the right answer is
"detect AND overlap secret"; label=false => the right answer is "do
not fire on this file".

This script does NOT modify scanner code; it's a scout for the next
round.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import random
import shutil
import subprocess
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import score  # noqa: E402


def per_scanner_findings_for_file(
    scanner: str,
    file_path: pathlib.Path,
) -> tuple[list[dict], bool, str]:
    """Run scanner on the single file's containing directory and
    return only findings that map back to file_path.

    Returns (findings_for_file, available, error_msg). Findings are
    filtered to those whose normalized file path matches file_path
    (basename match, since trufflehog/gitleaks may emit relative
    paths and keyhog absolute, depending on cwd)."""
    runner = score.SCANNERS.get(scanner)
    if runner is None:
        return [], False, f"unknown scanner {scanner!r}"
    try:
        findings = runner([file_path])
    except FileNotFoundError as exc:
        return [], False, str(exc)
    except subprocess.TimeoutExpired as exc:
        return [], True, f"timeout: {exc}"
    target_name = file_path.name
    target_str = str(file_path)
    out = []
    for f in findings:
        fpath = f.get("file") or ""
        if fpath == target_str or fpath.endswith("/" + target_name) or fpath == target_name:
            out.append(f)
    return out, True, ""


def attribute(rec: dict, findings_for_file: list[dict]) -> str:
    """Return 'TP' | 'FP' | 'TN' | 'FN' for this scanner on this fixture."""
    label = bool(rec.get("label"))
    if label:
        secret = rec.get("secret", "")
        for f in findings_for_file:
            if score.overlap(f.get("value", ""), secret):
                return "TP"
        if findings_for_file:
            # Fired but missed the labeled secret. Count as FN
            # (we missed the truth) and not FP, since on a label=true
            # fixture the file genuinely contains a secret and a hit
            # elsewhere on the line is still better than silence; the
            # paper's rule above counts these as FP at the corpus
            # level, but for a disagreement scout we care about
            # "missed the truth" so call it FN.
            return "FN"
        return "FN"
    # label=false
    return "FP" if findings_for_file else "TN"


def render_value(v: str, max_len: int = 80) -> str:
    if not v:
        return ""
    v = v.replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")
    if len(v) > max_len:
        return v[:max_len] + f"...<{len(v)-max_len} more chars>"
    return v


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--corpus", type=pathlib.Path,
                    default=pathlib.Path(
                        "/media/mukund-thiru/SanthData/Santh/software/keyhog/"
                        "tools/secretbench/mirror/corpus"))
    ap.add_argument("--sample-size", type=int, default=50)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--output", type=pathlib.Path, required=True)
    ap.add_argument("--scanners", nargs="+",
                    default=["keyhog", "trufflehog", "gitleaks"])
    args = ap.parse_args()

    records, root = score.load_corpus(args.corpus)
    print(f"loaded {len(records)} records from {root}", file=sys.stderr)

    rnd = random.Random(args.seed)
    sample = rnd.sample(records, k=min(args.sample_size, len(records)))
    print(f"sampled {len(sample)} (seed={args.seed})", file=sys.stderr)

    scanner_avail: dict[str, tuple[bool, str]] = {}
    for s in args.scanners:
        binary = s
        ok = shutil.which(binary) is not None
        scanner_avail[s] = (ok, "" if ok else f"binary {binary!r} not on PATH")
    print("scanner availability:", scanner_avail, file=sys.stderr)

    rows: list[dict] = []
    t0 = time.perf_counter()
    for i, rec in enumerate(sample):
        file_path = (root / rec["on_disk_path"]).resolve()
        row = {
            "id": rec["id"],
            "label": bool(rec["label"]),
            "category": rec.get("category", ""),
            "comment": rec.get("comment", ""),
            "file": str(file_path.relative_to(root)),
            "secret": rec.get("secret", ""),
            "scanners": {},
        }
        for s in args.scanners:
            if not scanner_avail[s][0]:
                row["scanners"][s] = {
                    "available": False,
                    "error": scanner_avail[s][1],
                    "attribution": "SKIP",
                    "findings": [],
                }
                continue
            findings, ok, err = per_scanner_findings_for_file(s, file_path)
            row["scanners"][s] = {
                "available": ok,
                "error": err,
                "attribution": attribute(rec, findings) if ok else "SKIP",
                "findings": [
                    {"value": f.get("value", ""),
                     "detector": f.get("detector", ""),
                     "line": f.get("line", 0)}
                    for f in findings
                ],
            }
        # right verdict from manifest
        row["expected"] = "TP" if row["label"] else "TN"
        # disagreement?
        atts = {s: row["scanners"][s]["attribution"]
                for s in args.scanners
                if row["scanners"][s]["available"]}
        row["attributions"] = atts
        row["disagreement"] = len(set(atts.values())) > 1
        rows.append(row)
        if (i + 1) % 5 == 0:
            print(f"  [{i+1}/{len(sample)}] elapsed {time.perf_counter()-t0:.1f}s",
                  file=sys.stderr)

    t1 = time.perf_counter()
    out = {
        "sample_size": len(sample),
        "seed": args.seed,
        "scanners": {s: {"available": ok, "error": err}
                     for s, (ok, err) in scanner_avail.items()},
        "elapsed_s": round(t1 - t0, 2),
        "rows": rows,
    }
    args.output.write_text(json.dumps(out, indent=2))
    print(f"wrote {args.output}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
