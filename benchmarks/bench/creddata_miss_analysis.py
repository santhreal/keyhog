"""CredData miss-ledger + candidate-detector evaluation (KH-L-0101/0102).

Two jobs, both grounded in the *real* CredData on-disk corpus:

1. ``shapes`` — for the recall-dominant miss categories (Key, UUID, Password,
   Secret, Token, Basic-Auth), slice every labeled value out of its on-disk
   span and bucket it by structural shape (pure hex of canonical key lengths,
   UUID, base64, other), split by whether a credential keyword precedes the
   value on the line. This is the precision/recall ground truth a candidate
   surfacing rule must clear: POS = real secrets of that shape, NEG = CredData
   negatives (placeholders / false positives) of the *same* shape. A rule that
   fires on the shape inherits exactly that POS/NEG split as its TP/FP ceiling.

2. ``simulate`` — apply a candidate finding-extractor (a set of line regexes)
   to every file referenced by the meta CSVs and score the extracted findings
   against ground truth with the SAME value-overlap rule the real bench uses
   (:func:`bench.score.overlap`), so a candidate detector's CredData recall /
   precision delta can be measured in seconds without rebuilding keyhog.

This never fabricates truth: a positive whose value can't be sliced from its
on-disk byte span is dropped, exactly as the production adapter does.
"""

from __future__ import annotations

import argparse
import collections
import csv
import glob
import math
import pathlib
import re
import sys

_BENCH_ROOT = pathlib.Path(__file__).resolve().parents[1]
_DEFAULT_CREDDATA = _BENCH_ROOT / "corpora" / "creddata" / "CredData"

HEX = re.compile(r"^[0-9a-fA-F]+$")
B64 = re.compile(r"^[A-Za-z0-9+/_=-]+$")
UUID = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
# A credential keyword immediately left of the value's `=`/`:` assignment.
KEYKW = re.compile(
    r"(?i)(?:^|[^a-z0-9_])"
    r"(key|secret|token|password|passwd|pwd|auth|credential|client[_-]?secret|"
    r"api[_-]?key|access[_-]?key|private[_-]?key|encryption[_-]?key|"
    r"signing[_-]?key)"
    r"[\"'` ]*[=:]"
)


def shannon(s: str) -> float:
    if not s:
        return 0.0
    counts = collections.Counter(s)
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def _shape(val: str) -> str:
    if UUID.match(val):
        return "uuid"
    if HEX.match(val):
        n = len(val)
        if n in (32, 48, 64):
            return f"hex{n}"
        return "hex<32" if n < 32 else "hex-other"
    if B64.match(val):
        return "b64"
    return "other"


class _LineCache:
    def __init__(self, root: pathlib.Path):
        self.root = root
        self._c: dict[str, list[str] | None] = {}

    def lines(self, rel: str) -> list[str] | None:
        if rel not in self._c:
            try:
                self._c[rel] = (self.root / rel).read_text(
                    encoding="latin-1"
                ).splitlines()
            except OSError:
                self._c[rel] = None
        return self._c[rel]


def _iter_meta(root: pathlib.Path):
    for csv_path in sorted((root / "meta").glob("*.csv")):
        with open(csv_path, newline="") as fh:
            for row in csv.DictReader(fh):
                yield row


def cmd_shapes(root: pathlib.Path) -> int:
    cache = _LineCache(root)
    target = {"Key", "UUID", "Password", "Secret", "Token",
              "Auth:Basic Authorization"}
    # (shape, keyword_present) -> Counter(POS/NEG)
    stat: dict[tuple[str, bool], collections.Counter] = collections.defaultdict(
        collections.Counter)
    by_cat: dict[str, collections.Counter] = collections.defaultdict(
        collections.Counter)
    for row in _iter_meta(root):
        gt = (row.get("GroundTruth") or "").strip().upper()
        label = "POS" if gt == "T" else "NEG"
        cat = (row.get("Category") or "").strip()
        ls = int(row.get("LineStart") or 0)
        vs = int(row.get("ValueStart") or -1)
        ve = int(row.get("ValueEnd") or -1)
        lines = cache.lines((row.get("FilePath") or "").strip())
        if not lines or ls < 1 or ls > len(lines) or vs < 0:
            continue
        line = lines[ls - 1]
        val = line[vs:(ve if ve >= 0 else None)]
        if not val:
            continue
        shape = _shape(val)
        kw = bool(KEYKW.search(line[:vs]))
        stat[(shape, kw)][label] += 1
        if cat in target:
            by_cat[cat][f"{label}:{shape}"] += 1

    print("== shape × keyword precision ceiling (all categories) ==")
    print(f"{'shape':10} {'kw':5} {'POS':>6} {'NEG':>6} {'precision':>10}")
    for (shape, kw), c in sorted(stat.items(),
                                 key=lambda kv: -kv[1]["POS"]):
        pos, neg = c["POS"], c["NEG"]
        if pos + neg < 20:
            continue
        prec = pos / (pos + neg) if pos + neg else 0.0
        print(f"{shape:10} {str(kw):5} {pos:6} {neg:6} {prec:10.3f}")
    return 0


# The keyword token immediately left of the value's `=`/`:` assignment, captured
# (not just detected) so we can bucket precision per keyword. Mirrors the shipped
# Rust canonicalisation (case-fold, strip `_-.`) so the strong-set decision the
# tool informs is the *same* comparison the scanner makes.
KW_TOKEN = re.compile(r"([A-Za-z][A-Za-z0-9_.\-]{1,40})[\"'` ]*[=:]\s*[\"'`]?$")


def _canon_kw(kw: str) -> str:
    return re.sub(r"[_.\-]", "", kw.lower())


def cmd_keywords(root: pathlib.Path) -> int:
    """Per-keyword POS/NEG precision for the mirror-safe lengths (hex32/hex48).

    The mirror plants ZERO hex32/hex48 negatives (only hex40/hex64), so a
    keyword-set broadening confined to lengths 32/48 cannot regress mirror
    precision. The only real-world FP cost lives on CredData; this command
    surfaces it per canonical keyword so the strong set can be extended only to
    keywords that clear a precision bar — soundness before reach.
    """
    cache = _LineCache(root)
    # canon_kw -> {len -> Counter(POS/NEG)}
    stat: dict[str, dict[int, collections.Counter]] = collections.defaultdict(
        lambda: collections.defaultdict(collections.Counter))
    for row in _iter_meta(root):
        gt = (row.get("GroundTruth") or "").strip().upper()
        label = "POS" if gt == "T" else "NEG"
        ls = int(row.get("LineStart") or 0)
        vs = int(row.get("ValueStart") or -1)
        ve = int(row.get("ValueEnd") or -1)
        lines = cache.lines((row.get("FilePath") or "").strip())
        if not lines or ls < 1 or ls > len(lines) or vs < 0:
            continue
        line = lines[ls - 1]
        val = line[vs:(ve if ve >= 0 else None)]
        if not val or not HEX.match(val) or len(val) not in (32, 48):
            continue
        m = KW_TOKEN.search(line[:vs])
        if not m:
            continue
        stat[_canon_kw(m.group(1))][len(val)][label] += 1

    # Flatten to (canon_kw) -> Counter over both lengths for ranking.
    rows = []
    for kw, by_len in stat.items():
        agg = collections.Counter()
        for c in by_len.values():
            agg.update(c)
        pos, neg = agg["POS"], agg["NEG"]
        if pos + neg < 5:
            continue
        prec = pos / (pos + neg)
        rows.append((kw, pos, neg, prec,
                     by_len.get(32, collections.Counter()),
                     by_len.get(48, collections.Counter())))

    print("== hex32/hex48 keyword-level precision (CredData; mirror-safe lengths) ==")
    print(f"{'canon_keyword':22} {'POS':>5} {'NEG':>5} {'prec':>6}  "
          f"{'h32 P/N':>10} {'h48 P/N':>10}")
    for kw, pos, neg, prec, c32, c48 in sorted(rows, key=lambda r: -r[1]):
        h32 = f"{c32['POS']}/{c32['NEG']}"
        h48 = f"{c48['POS']}/{c48['NEG']}"
        print(f"{kw:22} {pos:5} {neg:5} {prec:6.3f}  {h32:>10} {h48:>10}")
    tot_pos = sum(r[1] for r in rows)
    tot_neg = sum(r[2] for r in rows)
    print(f"\ntotal keyworded hex32/48: POS={tot_pos} NEG={tot_neg} "
          f"P={tot_pos/(tot_pos+tot_neg):.3f}" if tot_pos + tot_neg else "none")
    return 0


# ── candidate finding-extractors (line regexes -> (value) findings) ──────

def _extract_candidate(line: str, patterns: list[re.Pattern]) -> list[str]:
    out = []
    for pat in patterns:
        for m in pat.finditer(line):
            out.append(m.group(m.lastindex or 0))
    return out


CANDIDATES: dict[str, list[re.Pattern]] = {
    # `<key-keyword> = <pure hex of 32/48/64>` — canonical AES key lengths.
    "crypto_key_hex": [
        re.compile(
            r"(?i)(?:^|[^a-z0-9_])"
            r"(?:key|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|"
            r"encryption[_-]?key|signing[_-]?key|client[_-]?secret|master[_-]?key)"
            r"[\"'` ]*[=:]\s*[\"'`]?([0-9a-fA-F]{32}|[0-9a-fA-F]{48}|[0-9a-fA-F]{64})"
            r"(?![0-9a-fA-F])"
        )
    ],
    # `<cred-keyword> = <uuid>` — UUID used as a credential (keyword-anchored).
    "keyworded_uuid": [
        re.compile(
            r"(?i)(?:^|[^a-z0-9_])"
            r"(?:key|secret|token|auth|credential|client[_-]?secret|"
            r"api[_-]?key|access[_-]?key)"
            r"[\"'` ]*[=:]\s*[\"'`]?"
            r"([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
            r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12})"
        )
    ],
    # `Basic <base64>` / `Authorization: Basic <base64>`.
    "basic_auth": [
        re.compile(r"(?i)basic\s+([A-Za-z0-9+/]{16,}={0,2})")
    ],
}


def cmd_simulate(root: pathlib.Path, candidate: str) -> int:
    from bench.score import overlap  # same overlap rule as the real bench

    pats = CANDIDATES[candidate]
    cache = _LineCache(root)

    # Build per-file record lists (positives with sliced values + ignores).
    pos_by_file: dict[str, list[str]] = collections.defaultdict(list)
    ign_by_file: dict[str, list[str]] = collections.defaultdict(list)
    files: set[str] = set()
    for row in _iter_meta(root):
        rel = (row.get("FilePath") or "").strip()
        if not rel:
            continue
        files.add(rel)
        gt = (row.get("GroundTruth") or "").strip().upper()
        ls = int(row.get("LineStart") or 0)
        vs = int(row.get("ValueStart") or -1)
        ve = int(row.get("ValueEnd") or -1)
        lines = cache.lines(rel)
        if not lines or ls < 1 or ls > len(lines) or vs < 0:
            continue
        val = lines[ls - 1][vs:(ve if ve >= 0 else None)]
        if not val:
            continue
        if gt == "T":
            pos_by_file[rel].append(val)
        elif gt == "X":
            ign_by_file[rel].append(val)

    total_pos = sum(len(v) for v in pos_by_file.values())
    tp_records = 0
    fp = 0
    matched_pos: set[tuple[str, int]] = set()
    for rel in files:
        lines = cache.lines(rel)
        if not lines:
            continue
        for line in lines:
            for val in _extract_candidate(line, pats):
                if not val:
                    continue
                hit = False
                for i, sec in enumerate(pos_by_file.get(rel, [])):
                    if overlap(val, sec):
                        matched_pos.add((rel, i))
                        hit = True
                if hit:
                    continue
                if any(overlap(val, s) for s in ign_by_file.get(rel, [])):
                    continue
                fp += 1
    tp_records = len(matched_pos)
    prec = tp_records / (tp_records + fp) if (tp_records + fp) else 0.0
    print(f"candidate={candidate}")
    print(f"  new TP (positives caught) : {tp_records}")
    print(f"  new FP (on labeled files) : {fp}")
    print(f"  candidate precision       : {prec:.3f}")
    print(f"  (corpus positives total   : {total_pos})")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="CredData miss analysis")
    ap.add_argument("command", choices=("shapes", "simulate", "keywords"))
    ap.add_argument("--root", default=str(_DEFAULT_CREDDATA))
    ap.add_argument("--candidate", choices=tuple(CANDIDATES),
                    default="crypto_key_hex")
    args = ap.parse_args(argv)
    root = pathlib.Path(args.root)
    if not (root / "meta").is_dir():
        print(f"CredData meta missing under {root}", file=sys.stderr)
        return 2
    if args.command == "shapes":
        return cmd_shapes(root)
    if args.command == "keywords":
        return cmd_keywords(root)
    return cmd_simulate(root, args.candidate)


if __name__ == "__main__":
    raise SystemExit(main())
