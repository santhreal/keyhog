"""Overlap/attribution scorer (the SecretBench truth rules).

This is the legacy ``tools/secretbench/scoring/score.py`` attribution logic,
ported so the numbers are identical, with one generalisation: it groups
ground-truth records by file so a single file may carry several labeled
secrets (CredData). The single-record-per-file mirror corpus scores
bit-identically to the legacy scorer: ``test_score.py`` pins that.

Attribution (SecretBench paper, Basak et al. MSR 2023):

* **True positive**, a finding's surfaced value contains, or is contained
  in, a labeled secret on a positive record (``overlap`` rule below).
* **False positive**, a finding that overlaps no positive record on a
  known file (fires on a negative, or on a positive file but off-secret),
  or a finding on a file with no records at all.
* **False negative** (a positive record with no overlapping finding).
* **Ignored**, a finding overlapping an ``ignore`` record (CredData
  ``Template``/``X``) counts neither way; ignore records never produce FN.

``overlap`` / ``_normalize_for_overlap`` / ``_try_base64_decode`` are copied
verbatim from the legacy scorer, same robustness to redaction, escape-
sequence re-wrapping, and k8s base64 ``data:`` fields.
"""

from __future__ import annotations

import base64 as _b64
import pathlib
from collections import defaultdict

from .corpora.base import LabeledRecord
from .schema import Detection, DetectorStat, Outcome

# A normalised finding is a plain dict: {file, line, value, detector}, with
# optional scanner-specific evidence such as offset and confidence.
Finding = dict


# ── overlap rule (verbatim from legacy score.py) ──────────────────────

_ESCAPE_NORMALIZE = (
    ("\\n", "\n"),
    ("\\r", "\r"),
    ("\\t", "\t"),
    ("\\\\", "\\"),
)


def _try_base64_decode(s: str) -> str | None:
    """Return s base64-decoded as latin-1 text, or None. Lets a captured
    k8s ``data:`` value (base64) overlap a manifest plaintext secret, the
    underlying bytes are the same secret, only the surface differs. Mirror
    v28: 38 FPs traced to exactly this encoding mismatch. Conservative:
    16+ chars, base64 alphabet, decodes to 8+ bytes, so random ASCII won't
    fabricate TPs."""
    if len(s) < 16:
        return None
    needs_padding = len(s) % 4
    candidate = s + "=" * (4 - needs_padding) if needs_padding else s
    if not all(c.isalnum() or c in ("+", "/", "=", "-", "_") for c in candidate):
        return None
    try:
        raw = _b64.b64decode(candidate, validate=False)
    except Exception:
        return None
    if len(raw) < 8:
        return None
    try:
        return raw.decode("latin-1")
    except Exception:
        return None


def _normalize_for_overlap(s: str) -> str:
    """Collapse escaped (``\\n``) and raw (newline) forms so a multi-line
    secret (PEM key, service-account JSON) reported with literal ``\\n``
    overlaps the same key stored with real newlines. Mirror v22: 45
    false-FPs traced to this mismatch."""
    for esc, raw in _ESCAPE_NORMALIZE:
        s = s.replace(esc, raw)
    return s


def overlap(a: str, b: str) -> bool:
    """SecretBench containment rule: either side contains the other, after
    escape normalisation and a conservative base64 pass."""
    if not a or not b:
        return False
    if a in b or b in a:
        return True
    an, bn = _normalize_for_overlap(a), _normalize_for_overlap(b)
    if an in bn or bn in an:
        return True
    a_dec = _try_base64_decode(a)
    if a_dec and (a_dec in b or b in a_dec):
        return True
    b_dec = _try_base64_decode(b)
    if b_dec and (a in b_dec or b_dec in a):
        return True
    return False


# ── file-path indexing ────────────────────────────────────────────────


def _record_abs_path(rec: LabeledRecord, file_root: pathlib.Path) -> pathlib.Path:
    return file_root / rec.file_path


def _build_file_index(
    records: list[LabeledRecord], file_root: pathlib.Path
) -> tuple[dict[str, list[LabeledRecord]], dict[str, str]]:
    """Group records by file. Returns (by_key, key_aliases) where by_key maps
    a canonical key -> its records, and key_aliases maps every spelling of a
    path (resolved, unresolved, relative on_disk_path) to that canonical key
    so a finding's reported path resolves regardless of how the scanner
    spelled it (mirrors the legacy rec_by_path multi-key index)."""
    by_key: dict[str, list[LabeledRecord]] = defaultdict(list)
    aliases: dict[str, str] = {}
    for rec in records:
        abs_path = _record_abs_path(rec, file_root)
        key = str(abs_path)
        by_key[key].append(rec)
        aliases[key] = key
        try:
            aliases[str(abs_path.resolve())] = key
        except OSError:
            pass
        aliases[rec.file_path] = key
    return by_key, aliases


def _normalize_path_spelling(path: str) -> str:
    return path.replace("\\", "/").rstrip("/")


def _basename(norm_path: str) -> str:
    return norm_path.rsplit("/", 1)[-1]


def build_basename_index(aliases: dict[str, str]) -> dict[str, list[tuple[str, str]]]:
    """basename -> [(normalized spelling, canonical key)]. Built ONCE per file
    index; every non-exact path match (equality, "/"-suffix either direction,
    basename) preserves the final path component, so a finding only ever needs
    the candidates sharing its basename, turning the per-finding alias scan
    from O(all aliases) into O(same-basename aliases)."""
    index: dict[str, list[tuple[str, str]]] = defaultdict(list)
    for spelling, key in aliases.items():
        norm = _normalize_path_spelling(spelling)
        index[_basename(norm)].append((norm, key))
    return index


def _resolve_finding_file(
    fpath: str,
    aliases: dict[str, str],
    basename_index: dict[str, list[tuple[str, str]]] | None = None,
) -> str | None:
    """Map a finding's file path to a canonical record key. Exact first,
    then unique suffix/basename matching for scanners that report shortened
    paths. Ambiguous shortened paths return None instead of silently crediting
    a finding to whichever same-basename file appeared first."""
    if fpath in aliases:
        return aliases[fpath]
    matches = _resolve_finding_file_candidates(fpath, aliases, basename_index)
    if len(matches) == 1:
        return next(iter(matches))
    return None


def _resolve_finding_file_candidates(
    fpath: str,
    aliases: dict[str, str],
    basename_index: dict[str, list[tuple[str, str]]] | None = None,
) -> set[str]:
    if fpath in aliases:
        return {aliases[fpath]}
    needle = _normalize_path_spelling(fpath)
    if not needle:
        return set()
    if basename_index is None:
        basename_index = build_basename_index(aliases)
    candidates = basename_index.get(_basename(needle), [])
    tail_matches: set[str] = set()
    for haystack, key in candidates:
        if (
            haystack == needle
            or haystack.endswith("/" + needle)
            or needle.endswith("/" + haystack)
        ):
            tail_matches.add(key)
    if tail_matches:
        return tail_matches
    # No "/"-anchored suffix match. A finding path that CARRIES directory
    # structure (contains a "/") but matches no record's path is a file the
    # corpus simply does not label, e.g. a duplicate-basename doc in a snapshot
    # whose *other* files are labeled (CredData has 60+ files named
    # `b3356305.md`). Resolve it to "no record" (empty) so the finding is
    # skipped, NEVER blamed on the dozens of unrelated same-basename files: that
    # spurious ambiguity crashed the harvest's exact-path guard. The
    # same-basename fallback is only meaningful for a scanner that reports a BARE
    # basename, where the basename is the only disambiguating signal available.
    if "/" in needle:
        return set()
    return {key for _haystack, key in candidates}


def _file_category(recs: list[LabeledRecord]) -> str:
    """Category an off-secret FP on this file is attributed to: the first
    positive record's category, else the first record's, else 'unknown'."""
    for r in recs:
        if r.label and not r.ignore:
            return r.category or "unknown"
    return (recs[0].category if recs else "unknown") or "unknown"


# ── per-record recall hit-set ──────────────────────────────────────────


def found_record_ids(
    records: list[LabeledRecord],
    findings: list[Finding],
    file_root: pathlib.Path,
) -> set[str]:
    """Return the ids of the POSITIVE records (``label and not ignore``) that
    at least one finding's value overlaps.

    This is the per-record recall hit-set that :func:`score` computes
    internally (its ``hit_ids``) but does not expose. It reuses the SAME file
    index, path resolution, and :func:`overlap` rule, so a record id is in this
    set iff that record is a true positive in :func:`score`: the per-secret
    recall matrix (``test_creddata_recall_matrix``) asserts membership here, and
    its module pins ``len(found_record_ids(...)) == score(...).overall.tp`` so
    the two can never drift. Kept a thin standalone helper (not folded into
    ``score``) because ``score`` additionally threads per-detector confidence
    bookkeeping that a recall hit-set does not need."""
    by_key, aliases = _build_file_index(records, file_root)
    basename_index = build_basename_index(aliases)
    found: set[str] = set()
    for f in findings:
        fpath = f.get("file") or ""
        key = _resolve_finding_file(fpath, aliases, basename_index) if fpath else None
        if key is None:
            continue
        value = f.get("value") or ""
        for rec in by_key[key]:
            if rec.label and not rec.ignore and overlap(value, rec.secret):
                found.add(rec.id)
    return found


# ── the scorer ─────────────────────────────────────────────────────────


def _max_conf(a: float | None, b: float | None) -> float | None:
    """Carry the higher confidence of two findings that hit the same record;
    ``None`` (scanner reported no confidence) loses to any real value."""
    if a is None:
        return b
    if b is None:
        return a
    return a if a >= b else b


def score(
    records: list[LabeledRecord],
    findings: list[Finding],
    file_root: pathlib.Path,
) -> Detection:
    """Attribute ``findings`` against ground-truth ``records``.

    Populates ``per_category`` (taxonomy buckets) and ``per_detector``
    (keyhog detector id) confusion matrices. Per-detector FP is per-finding;
    per-detector TP is per-record (deduped), so a detector that fires three
    times on one secret scores one TP (matching the overall TP semantics).
    A record's TP confidence is the max over the findings that caught it.
    """
    det = Detection()
    per_cat: dict[str, Outcome] = defaultdict(Outcome)
    per_det: dict[str, DetectorStat] = defaultdict(DetectorStat)

    by_key, aliases = _build_file_index(records, file_root)
    basename_index = build_basename_index(aliases)
    hit_ids: set[str] = set()
    # record id -> {detector_id: max confidence of a finding that caught it}
    record_hits: dict[str, dict[str, float | None]] = defaultdict(dict)
    fp_total = 0

    for f in findings:
        detector = f.get("detector") or ""
        conf = f.get("confidence")
        fpath = f.get("file") or ""
        key = _resolve_finding_file(fpath, aliases, basename_index) if fpath else None
        if key is None:
            # Finding on a file with no record at all -> false positive.
            fp_total += 1
            per_cat["unknown"].fp += 1
            per_det[detector].add_fp(conf)
            continue
        recs = by_key[key]
        value = f.get("value") or ""

        # Did it overlap a positive secret on this file?
        matched_positive = False
        for rec in recs:
            if rec.label and not rec.ignore and overlap(value, rec.secret):
                hit_ids.add(rec.id)
                matched_positive = True
                hits = record_hits[rec.id]
                hits[detector] = _max_conf(hits.get(detector), conf)
        if matched_positive:
            continue

        # Did it overlap an ignore record? Drop it (counts neither way).
        if any(rec.ignore and overlap(value, rec.secret) for rec in recs):
            continue

        # Otherwise: a finding on a known file that hit no positive secret.
        fp_total += 1
        per_cat[_file_category(recs)].fp += 1
        per_det[detector].add_fp(conf)

    # Per-detector TP + unique_tp, attributed per caught record.
    for hits in record_hits.values():
        for detector, conf in hits.items():
            per_det[detector].add_tp(conf)
        if len(hits) == 1:
            per_det[next(iter(hits))].unique_tp += 1

    # Credit TP/FN per positive record.
    for rec in records:
        if not rec.label or rec.ignore:
            continue
        cat = rec.category or "unknown"
        if rec.id in hit_ids:
            det.overall.tp += 1
            per_cat[cat].tp += 1
        else:
            det.overall.fn += 1
            per_cat[cat].fn += 1

    det.overall.fp = fp_total
    det.per_category = dict(per_cat)
    det.per_detector = dict(per_det)
    return det
