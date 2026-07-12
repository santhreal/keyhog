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

3. ``keywords`` — bucket the mirror-safe lengths by canonical assignment
   keyword, to separate genuinely-distributed recall headroom from single-
   fixture artifacts before committing to a shape+keyword surfacing rule.

4. ``decompose`` — using a built keyhog binary's ``--dogfood`` suppression
   trace, bucket every T-positive into TP / SUPPRESSED-by-gate (with a per-gate
   reason histogram) / NEVER-CANDIDATE, so recall loss is attributed to
   candidate GENERATION (un-generated) vs suppression (recoverable by gate
   relaxation). Requires ``--scanner-bin``.

This never fabricates truth: a positive whose value can't be sliced from its
on-disk byte span is dropped, exactly as the production adapter does.
"""

from __future__ import annotations

import argparse
import collections
import csv
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

from .corpora.creddata import _slice_value_from_lines
from .textstats import shannon_entropy as shannon

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
        le = int(row.get("LineEnd") or 0)
        vs = int(row.get("ValueStart") or -1)
        ve = int(row.get("ValueEnd") or -1)
        lines = cache.lines((row.get("FilePath") or "").strip())
        if not lines or ls < 1 or ls > len(lines) or vs < 0:
            continue
        line = lines[ls - 1]
        val = _slice_value_from_lines(lines, ls, le, vs, ve)
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
        le = int(row.get("LineEnd") or 0)
        vs = int(row.get("ValueStart") or -1)
        ve = int(row.get("ValueEnd") or -1)
        lines = cache.lines((row.get("FilePath") or "").strip())
        if not lines or ls < 1 or ls > len(lines) or vs < 0:
            continue
        line = lines[ls - 1]
        val = _slice_value_from_lines(lines, ls, le, vs, ve)
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
    # hex64 (32-byte / AES-256 key length) under the NARROW strong cryptographic
    # keyword family ONLY (excludes bare `key`/`secret` to isolate the
    # mirror-safe precision of the strong-anchor subset that the shipped
    # `is_strong_keyword_anchored_hex_key` currently excludes at len 64).
    "crypto_key_hex64_strong": [
        re.compile(
            r"(?i)(?:^|[^a-z0-9_])"
            r"(?:encryption[_-]?key|private[_-]?key|signing[_-]?key|master[_-]?key|"
            r"access[_-]?key|api[_-]?key|client[_-]?secret|app[_-]?secret|aes[_-]?key|"
            r"secret[_-]?key)"
            r"[\"'` ]*[=:]\s*[\"'`]?([0-9a-fA-F]{64})(?![0-9a-fA-F])"
        )
    ],
    # hex64 under the BARE `key`/`secret` anchors only — the more ambiguous tail
    # whose precision must be inspected separately before any broadening.
    "crypto_key_hex64_bare": [
        re.compile(
            r"(?i)(?:^|[^a-z0-9_])(?:key|secret)"
            r"[\"'` ]*[=:]\s*[\"'`]?([0-9a-fA-F]{64})(?![0-9a-fA-F])"
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
    # The current shipped `jwt-token` named detector anchors on the literal
    # `eyJhbGci` prefix (base64url of `{"alg":`). A JWT whose JSON header puts
    # `typ` or `jwk` BEFORE `alg` begins `eyJ0eXAi` (`{"typ":`) / `eyJqd2si`
    # (`{"jwk":`) and is MISSED. This candidate measures the recall+precision of
    # anchoring on the structural JWT shape (any `eyJ`-header base64url triple)
    # instead of the single header-field-order prefix.
    "jwt_any_header": [
        re.compile(
            r"\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})"
        )
    ],
    # The header-order-broadened JWT the shipped regex misses: a JWT whose first
    # header field is NOT `alg` (so it does not start `eyJhbGci`). Isolates the
    # exact incremental recall the detector broadening recovers, with its own
    # precision.
    "jwt_non_alg_first": [
        re.compile(
            r"\b(eyJ(?!hbGci)[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}"
            r"\.[A-Za-z0-9_-]{10,})"
        )
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
        le = int(row.get("LineEnd") or 0)
        vs = int(row.get("ValueStart") or -1)
        ve = int(row.get("ValueEnd") or -1)
        lines = cache.lines(rel)
        if not lines or ls < 1 or ls > len(lines) or vs < 0:
            continue
        val = _slice_value_from_lines(lines, ls, le, vs, ve)
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


def _redact(s: str) -> str:
    """Mirror ``keyhog_core::redact``: <=8 ASCII chars -> ``****`` else
    first4 + ``...`` + last4. Used to join a `--dogfood` suppression event's
    redacted credential back to its ground-truth value."""
    return "****" if len(s) <= 8 else s[:4] + "..." + s[-4:]


def cmd_decompose(root: pathlib.Path, scanner_bin: str, backend: str = "simd") -> int:
    """Bucket every CredData T-positive into TP / SUPPRESSED-by-gate / NEVER-
    CANDIDATE using the scanner's ``--dogfood`` suppression trace (KH-L-0408/
    0409/0412). Answers *where* recall is lost: a value that no detector emits
    AND no suppression gate names is truly un-generated (candidate-generation
    bound); a value a gate suppresses is recoverable by relaxing that gate. The
    per-gate reason histogram pinpoints which gates hold real positives.

    Scans a temp tree of only the positive-bearing files (``keyhog scan`` takes a
    single PATH), once, with ``--dogfood --show-secrets``. Promoted from the
    throwaway probe script so the recall decomposition has a canonical home."""
    cache = _LineCache(root)
    # 1. collect T-positives with on-disk values, keyed by rel path.
    pos: list[tuple[str, str]] = []
    for row in _iter_meta(root):
        if (row.get("GroundTruth") or "").strip().upper() != "T":
            continue
        rel = (row.get("FilePath") or "").strip()
        try:
            ls = int(row.get("LineStart") or 0)
            le = int(row.get("LineEnd") or 0)
            vs = int(row.get("ValueStart") or -1)
            ve = int(row.get("ValueEnd") or -1)
        except ValueError:
            continue
        lines = cache.lines(rel)
        if not lines or ls < 1 or ls > len(lines) or vs < 0:
            continue
        val = _slice_value_from_lines(lines, ls, le, vs, ve)
        if val:
            pos.append((rel, val))
    rels = sorted({r for r, _ in pos})
    print(f"T-positives w/ value: {len(pos)} across {len(rels)} files",
          file=sys.stderr)

    # 2. copy positive-bearing files into a temp tree, scan once.
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="creddata-decompose-"))
    try:
        for rel in rels:
            dst = tmp / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(root / rel, dst)
        # Force an explicit backend: a default `auto` scan fail-closes demanding
        # autoroute calibration (no persisted decision for this workload bucket),
        # which would abort the diagnostic. Findings are backend-invariant, so
        # `simd` gives the same recall map without priming the autoroute cache.
        try:
            proc = subprocess.run(
                [scanner_bin, "scan", "--path", str(tmp), "--backend", backend,
                 "--dogfood", "--show-secrets", "--format", "jsonl"],
                capture_output=True, text=True, timeout=3600,
            )
        except subprocess.TimeoutExpired:
            print("scan timed out after 3600s", file=sys.stderr)
            return 1
        if proc.returncode not in (0, 1):
            print(f"scan failed rc={proc.returncode}: {proc.stderr[:500]}",
                  file=sys.stderr)
            return 1

        def to_rel(p: str) -> str:
            ap = os.path.abspath(p)
            pre = str(tmp) + os.sep
            return ap[len(pre):] if ap.startswith(pre) else ap

        # 3. findings (stdout jsonl) + dogfood suppression events (stderr json).
        finds: dict[str, list[str]] = collections.defaultdict(list)
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                d = json.loads(line)
            except json.JSONDecodeError:
                continue
            loc = d.get("location") or {}
            fp = loc.get("file_path") or loc.get("file") or ""
            cred = d.get("credential") or d.get("credential_redacted") or ""
            if fp and cred:
                finds[to_rel(fp)].append(cred)
        supp: dict[str, set[tuple[str, str]]] = collections.defaultdict(set)
        for line in proc.stderr.splitlines():
            line = line.strip()
            if not line.startswith("{") or "dogfood" not in line:
                continue
            try:
                d = json.loads(line)
            except json.JSONDecodeError:
                continue
            for ev in (d.get("dogfood") or {}).get("events", []):
                supp[to_rel(ev.get("path") or "")].add(
                    (ev.get("credential_redacted", ""), ev.get("reason", "")))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    # 4. bucket each positive.
    bucket: collections.Counter = collections.Counter()
    reason: collections.Counter = collections.Counter()
    for rel, val in pos:
        is_uuid = bool(UUID.match(val))
        if any(val == c or val in c or c in val for c in finds.get(rel, [])):
            bucket["TP_uuid" if is_uuid else "TP"] += 1
            continue
        rv = _redact(val)
        matched = [r for (cr, r) in supp.get(rel, set()) if cr == rv]
        if matched:
            bucket["SUPPRESSED_uuid" if is_uuid else "SUPPRESSED"] += 1
            if not is_uuid:
                reason[matched[0]] += 1
        else:
            bucket["NEVERCAND_uuid" if is_uuid else "NEVERCAND"] += 1

    total = sum(bucket.values()) or 1
    print("\n=== CredData recall decomposition (T-positives) ===")
    for key, n in bucket.most_common():
        print(f"  {key:18} {n:6}  ({100 * n / total:.1f}%)")
    print("\n=== suppressed-by-gate (non-UUID) reason histogram ===")
    for r, c in reason.most_common():
        print(f"  {c:5}  {r}")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="CredData miss analysis")
    ap.add_argument("command",
                    choices=("shapes", "simulate", "keywords", "decompose"))
    ap.add_argument("--root", default=str(_DEFAULT_CREDDATA))
    ap.add_argument("--candidate", choices=tuple(CANDIDATES),
                    default="crypto_key_hex")
    ap.add_argument("--scanner-bin", default="keyhog",
                    help="keyhog binary for `decompose` (uses --dogfood trace)")
    ap.add_argument("--backend", default="simd",
                    help="explicit scan backend for `decompose` (default simd; "
                         "avoids the auto-backend autoroute-calibration fail-closed)")
    args = ap.parse_args(argv)
    root = pathlib.Path(args.root)
    if not (root / "meta").is_dir():
        print(f"CredData meta missing under {root}", file=sys.stderr)
        return 2
    if args.command == "shapes":
        return cmd_shapes(root)
    if args.command == "keywords":
        return cmd_keywords(root)
    if args.command == "decompose":
        return cmd_decompose(root, args.scanner_bin, args.backend)
    return cmd_simulate(root, args.candidate)


if __name__ == "__main__":
    raise SystemExit(main())
