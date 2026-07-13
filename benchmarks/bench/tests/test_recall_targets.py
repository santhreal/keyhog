"""CredData recall TARGET-SPEC worklist (the failing recall gaps, named).

Distinct from ``test_creddata_recall_matrix`` (a per-secret REGRESSION ratchet
pinned to today's measured 2504 and therefore GREEN). This module encodes the
TARGET keyhog must reach but does NOT today, so every assertion here is RED
until candidate generation closes the gap. Each red is a tracked recall finding
(Law 6, a failing contract test is the worklist), never a decoration and never
weakened to pass (Law 9).

Two target tiers, both scored through the SAME ``KeyhogScanner`` adapter,
``CredDataCorpus`` slicing, and ``score.overlap``/``found_record_ids`` truth
rule the leaderboard uses, so a red here is bit-identical to a leaderboard
false negative, not a separate yardstick:

1. **Overall recall >= 0.90.** CredData recall is ~0.18 today (2504 of 13918
   value-anchored positives). This is the headline target; it fails by a wide
   margin and stays red until the generation gap closes.

2. **Per-miss-class floors.** The overall number averages away which credential
   SHAPES the scanner is blind to. Each positive's literal value is sliced from
   its on-disk byte span and bucketed by structure (the same ``_shape`` rule
   ``creddata_miss_analysis`` uses), and per-class recall is asserted against a
   target floor:

       hex64 >= 0.85   uuid >= 0.85   base64 >= 0.80
       jwt   >= 0.90   keyword-anchored >= 0.85

   ``keyword-anchored`` is a CROSS-cutting class (any shape whose value is
   preceded by a credential keyword on its line), so it overlaps the shape
   classes: it isolates the "a human wrote ``api_key = <value>`` and we still
   missed it" failure mode that the generation gap is most accountable for.

LOUD on absence (never a silent green):
* CredData corpus absent (``make creddata``) -> the module skips with reason.
* No keyhog binary -> the scan fixture FAILS loudly (a missing binary must
  never masquerade as 100% recall loss, nor as a passed target).

The floors are intentionally the PRODUCT targets, not today's measurements: a
ratchet pins what we have, a target spec pins what we owe. When generation lands
and a class clears its floor, that class flips green here without any edit, the
worklist shrinks by itself.
"""

from __future__ import annotations

import re

import pytest

pytestmark = pytest.mark.target_spec

from bench.corpora.creddata import CredDataCorpus
from bench.scanners.keyhog import KeyhogScanner, resolve_keyhog_binary
from bench.schema import ScannerConfig
from bench.score import found_record_ids, score

# ── corpus load (collection time) ─────────────────────────────────────

_CORPUS = CredDataCorpus()
_AVAILABLE = _CORPUS.is_downloaded()
_RECORDS = _CORPUS.records() if _AVAILABLE else []
_POSITIVES = [r for r in _RECORDS if r.label and not r.ignore]


# ── miss-class shape classification (mirrors creddata_miss_analysis._shape) ──
# Each ground-truth value is bucketed by the SAME structural rule the miss
# ledger uses, so a class floor here is measured against the exact shape pool
# the surfacing work targets, no second, drifting definition of "what a hex64
# secret is".

_UUID = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_HEX = re.compile(r"^[0-9a-fA-F]+$")
_B64 = re.compile(r"^[A-Za-z0-9+/_=-]+$")
# Structural JWT: three base64url segments, first two are JSON-object headers
# (`eyJ` = base64url of `{"`). Matches anywhere on the value (a JWT is often a
# substring of a larger `Authorization: Bearer <jwt>` capture).
_JWT = re.compile(
    r"eyJ[A-Za-z0-9_-]{6,}\.eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{4,}"
)

# A credential keyword immediately left of the value's `=`/`:` assignment, the
# same anchor ``creddata_miss_analysis.KEYKW`` uses, so the keyword-anchored
# class here is the exact pool the keyword-bridge surfacing work is graded on.
_KEYKW = re.compile(
    r"(?i)(?:^|[^a-z0-9_])"
    r"(key|secret|token|password|passwd|pwd|auth|credential|client[_-]?secret|"
    r"api[_-]?key|access[_-]?key|private[_-]?key|encryption[_-]?key|"
    r"signing[_-]?key)"
    r"[\"'` ]*[=:]"
)


def _shape_class(value: str) -> str:
    """Bucket a sliced secret value into one miss-class shape, or 'other'."""
    v = value.strip()
    if _JWT.search(v):
        return "jwt"
    if _UUID.match(v):
        return "uuid"
    if _HEX.match(v):
        n = len(v)
        if n == 64:
            return "hex64"
        return "hex-other"
    if _B64.match(v) and len(v) >= 16:
        return "base64"
    return "other"


def _line_for(rec) -> str:
    """The on-disk source line a record's value sits on, latin-1 decoded so
    arbitrary source bytes never raise. '' if the file/line is unreadable 
    such a record simply can't be keyword-classified (counts as no-keyword)."""
    try:
        path = _CORPUS.file_root / rec.file_path
        with open(path, "r", encoding="latin-1") as fh:
            lines = fh.read().splitlines()
    except OSError:
        return ""
    idx = rec.line_start - 1
    if 0 <= idx < len(lines):
        return lines[idx]
    return ""


def _is_keyword_anchored(rec) -> bool:
    """True if a credential keyword precedes this record's value on its line.
    Anchored on the text LEFT of the value so a keyword inside the value (a
    random secret that happens to contain 'key') does not count."""
    line = _line_for(rec)
    if not line or not rec.secret:
        return False
    pos = line.find(rec.secret)
    left = line[:pos] if pos > 0 else line
    return bool(_KEYKW.search(left))


# Pre-bucket positives once (collection time) so each class test reads its pool
# without re-slicing. A record can appear in at most one SHAPE class and may
# also appear in the keyword-anchored class (cross-cutting).
_BY_SHAPE: dict[str, list] = {}
_KEYWORD_ANCHORED: list = []
for _r in _POSITIVES:
    _BY_SHAPE.setdefault(_shape_class(_r.secret), []).append(_r)
    if _is_keyword_anchored(_r):
        _KEYWORD_ANCHORED.append(_r)


# ── one scan, shared by every target assertion ─────────────────────────


@pytest.fixture(scope="session")
def recalled_ids():
    """Run keyhog ONCE over the full CredData corpus and return the set of
    positive record ids whose secret was surfaced. Zero findings, or a hit-set
    that disagrees with the canonical scorer, is a harness failure (wrong/broken
    binary) and fails LOUD, it must never read as a recall result, pass OR
    fail, off a binary that never ran correctly."""
    binary = resolve_keyhog_binary()
    if binary is None:
        pytest.fail(
            "no keyhog binary found (set KEYHOG_BIN, or build a release binary "
            "with `cargo build --release`); refusing to score recall targets off "
            "a binary that never ran")

    cfg = ScannerConfig(backend="simd", cache="off", daemon="off", mode="full")
    findings, _stats = KeyhogScanner(binary=binary).run(_CORPUS.scan_root, cfg)

    if not findings:
        pytest.fail(
            f"keyhog ({binary}) produced ZERO findings over CredData, a harness "
            f"failure (wrong binary / corpus path / scan error), not a recall "
            f"result. scan_root={_CORPUS.scan_root}")

    found = found_record_ids(_RECORDS, findings, _CORPUS.file_root)
    tp = score(_RECORDS, findings, _CORPUS.file_root).overall.tp
    assert len(found) == tp, (
        f"recall hit-set ({len(found)}) disagrees with the canonical scorer's "
        f"TP ({tp}), found_record_ids drifted from score(); fix before trusting "
        f"any recall target verdict")
    return found


def _class_recall(recs: list, recalled: set) -> tuple[int, int, float]:
    total = len(recs)
    hit = sum(1 for r in recs if r.id in recalled)
    return hit, total, (hit / total if total else 0.0)


# ── TARGET 1: overall recall >= 0.90 (the headline; ~0.18 today) ───────


_OVERALL_RECALL_TARGET = 0.90


@pytest.mark.skipif(
    not _AVAILABLE,
    reason="CredData corpus not on disk (benchmarks/corpora/creddata/CredData; "
           "run `make creddata`), recall targets cannot be scored")
def test_creddata_overall_recall_meets_target(recalled_ids):
    hit = len(recalled_ids)
    total = len(_POSITIVES)
    recall = hit / total if total else 0.0
    assert recall >= _OVERALL_RECALL_TARGET, (
        f"CredData OVERALL recall {recall:.4f} ({hit}/{total} value-anchored "
        f"positives) is below the product target {_OVERALL_RECALL_TARGET:.2f}. "
        f"This is the headline recall gap: {total - hit} real, human-reviewed "
        f"credentials the shipped `keyhog scan` does not surface. RED until "
        f"candidate generation closes the gap, do NOT lower this target (Law 9).")


# ── TARGET 2: per-miss-class recall floors ─────────────────────────────
# (class, floor, min_pool), min_pool guards against grading a class that is
# too small to be a real target on this corpus revision (none are, today; the
# guard keeps the spec honest if a future CredData pin shrinks a pool).

_CLASS_FLOORS: list[tuple[str, float, int]] = [
    ("hex64", 0.85, 50),
    ("uuid", 0.85, 50),
    ("base64", 0.80, 50),
    ("jwt", 0.90, 20),
]


@pytest.mark.skipif(
    not _AVAILABLE,
    reason="CredData corpus not on disk, per-class recall floors cannot run")
@pytest.mark.parametrize("klass,floor,min_pool", _CLASS_FLOORS,
                         ids=[c for c, _, _ in _CLASS_FLOORS])
def test_creddata_miss_class_recall_floor(klass, floor, min_pool, recalled_ids):
    recs = _BY_SHAPE.get(klass, [])
    assert len(recs) >= min_pool, (
        f"miss-class {klass!r} has only {len(recs)} value-anchored positives on "
        f"this CredData pin (< {min_pool}); too small to grade as a recall "
        f"target, re-bucket or bump the pin, do not silently pass.")
    hit, total, recall = _class_recall(recs, recalled_ids)
    assert recall >= floor, (
        f"CredData {klass!r} recall {recall:.4f} ({hit}/{total}) is below the "
        f"target floor {floor:.2f}. keyhog is largely blind to the {klass!r} "
        f"shape: {total - hit} real {klass!r} secrets go un-surfaced. The miss "
        f"is candidate GENERATION (a keyword-anchored {klass!r} value never "
        f"becomes a candidate), not suppression. RED until generation lands.")


# ── TARGET 2b: keyword-anchored recall floor (cross-cutting) ───────────
# The most accountable gap: a value a human wrote behind a credential keyword
# (`api_key = <value>`) that keyhog still misses. This pool spans every shape;
# its floor is the strongest single statement that the keyword bridge surfaces
# what an operator would obviously call a secret.

_KEYWORD_ANCHORED_FLOOR = 0.85


@pytest.mark.skipif(
    not _AVAILABLE,
    reason="CredData corpus not on disk, keyword-anchored floor cannot run")
def test_creddata_keyword_anchored_recall_floor(recalled_ids):
    recs = _KEYWORD_ANCHORED
    assert len(recs) >= 100, (
        f"keyword-anchored pool is only {len(recs)} positives (< 100), too "
        f"small to grade; the keyword classifier or corpus pin changed.")
    hit, total, recall = _class_recall(recs, recalled_ids)
    assert recall >= _KEYWORD_ANCHORED_FLOOR, (
        f"CredData KEYWORD-ANCHORED recall {recall:.4f} ({hit}/{total}) is below "
        f"the target floor {_KEYWORD_ANCHORED_FLOOR:.2f}. These are values a "
        f"human wrote directly behind a credential keyword "
        f"(`api_key = <value>`); {total - hit} of them are missed. That is the "
        f"clearest candidate-generation debt the keyword bridge owes. RED until "
        f"the bridge surfaces them, do NOT weaken this floor (Law 9).")
