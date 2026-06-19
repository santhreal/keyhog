"""Per-secret CredData recall matrix — one test per ground-truth secret.

The aggregate bench reports CredData recall as a single fraction. That number
hides *which* real credentials the shipped scanner misses, and lets a per-class
recall regression average away. This matrix turns EACH human-reviewed CredData
positive into its own named assertion: the scan runs ONCE (session fixture)
through the same ``KeyhogScanner`` adapter and ``score.overlap`` truth rule the
leaderboard uses, and every positive whose secret keyhog does not surface is a
RED case naming the exact file, line, and credential category it missed.

Law 6 — a failing contract test is a finding: every red case here is a real
secret the shipped operator path (``keyhog scan``) does not detect, not a
shape/parsing decoration. There is no fabricated failure — a positive is only
loaded if its literal value can be sliced from its on-disk byte span (the
corpus adapter drops un-anchorable rows), and a case is red only if no surfaced
finding's value overlaps that span.

The matrix is also a recall *regression guard*: a detection change that drops a
previously-found CredData secret flips its specific case from green to red, so
the loss is attributed to one secret, not buried in a 0.003 aggregate drift.

Requirements (both checked, both LOUD on absence — never a silent green):
* the CredData corpus on disk (``benchmarks/corpora/creddata/CredData``;
  ``make creddata``); absent => the whole module skips with that reason.
* a built keyhog binary — ``KEYHOG_BIN``, else a freshly-built release binary,
  else a ``release``/``release-fast`` binary in the repo's cargo target dir;
  none found => the scan fixture fails LOUDLY (a missing binary is a harness
  error, never 10k misleading recall reds).
"""

from __future__ import annotations

import pytest

from bench.corpora.creddata import CredDataCorpus
from bench.keyhog_version import KeyhogVersionError, assert_keyhog_binary_current
from bench.scanners.keyhog import KeyhogScanner, resolve_keyhog_binary
from bench.schema import ScannerConfig
from bench.score import found_record_ids, score

# ── corpus load (collection time) ─────────────────────────────────────

_CORPUS = CredDataCorpus()
_AVAILABLE = _CORPUS.is_downloaded()
# Load records once at import so both the parametrize list and the scan
# fixture share one slice pass (records() reads ~11k files off disk).
_RECORDS = _CORPUS.records() if _AVAILABLE else []
_POSITIVES = [r for r in _RECORDS if r.label and not r.ignore]


# ── one scan, shared by every case ────────────────────────────────────


@pytest.fixture(scope="session")
def scan_result():
    """Run keyhog ONCE over the full CredData corpus and return the set of
    positive record ids whose secret was surfaced. A scan that produces no
    findings, or whose recall hit-set disagrees with the canonical
    :func:`score`, is a harness failure (broken/wrong binary) and fails LOUD —
    it must never masquerade as a corpus-wide recall miss."""
    binary = resolve_keyhog_binary()
    if binary is None:
        pytest.fail(
            "no keyhog binary found (set KEYHOG_BIN, or build a release binary "
            "with `cargo build --release`); refusing to report every CredData "
            "secret as missed off a binary that never ran")
    try:
        assert_keyhog_binary_current(binary)
    except KeyhogVersionError as exc:
        pytest.fail(f"{exc}; refusing to score CredData recall with a stale binary")

    cfg = ScannerConfig(backend="simd", cache="off", daemon="off", mode="full")
    findings, _stats = KeyhogScanner(binary=binary).run(_CORPUS.scan_root, cfg)

    if not findings:
        pytest.fail(
            f"keyhog ({binary}) produced ZERO findings over CredData — a harness "
            f"failure (wrong binary / corpus path / scan error), not a recall "
            f"result. scan_root={_CORPUS.scan_root}")

    found = found_record_ids(_RECORDS, findings, _CORPUS.file_root)
    # Coherence: the recall hit-set MUST equal the canonical scorer's TP count,
    # so a per-secret red here is bit-identical to a false-negative there. If
    # these drift, the matrix is lying about what the leaderboard scored.
    tp = score(_RECORDS, findings, _CORPUS.file_root).overall.tp
    assert len(found) == tp, (
        f"recall hit-set ({len(found)}) disagrees with the canonical scorer's "
        f"TP ({tp}) — found_record_ids drifted from score(); fix before trusting "
        f"any per-secret verdict")
    return found


# ── the matrix: one assertion per ground-truth secret ─────────────────


@pytest.mark.skipif(
    not _AVAILABLE,
    reason="CredData corpus not on disk (benchmarks/corpora/creddata/CredData; "
           "run `make creddata`) — recall matrix cannot be scored")
@pytest.mark.parametrize(
    "rec",
    _POSITIVES,
    ids=[f"{r.category}:{r.file_path}:{r.line_start}" for r in _POSITIVES],
)
def test_creddata_secret_is_recalled(rec, scan_result):
    assert rec.id in scan_result, (
        f"keyhog did not surface the CredData {rec.category!r} secret at "
        f"{rec.file_path}:{rec.line_start} (record {rec.id}). The credential is "
        f"present and human-reviewed in CredData; this is a real recall miss.")


# ── category blind-spot gate ──────────────────────────────────────────
# Distinct from the per-secret matrix: a credential CATEGORY that keyhog
# recalls ZERO of (despite a meaningful sample of real positives) is not a
# scattering of hard individual misses — it is a detector CLASS the shipped
# scanner is wholly blind to. The per-secret matrix would show that as N red
# cases that look like the rest; this names the systemic hole directly. Only
# categories with enough positives to be statistically real are gated (a
# 2-positive category recalling 0 is noise, not a blind class).

_CATEGORY_MIN_POSITIVES = 25

_POSITIVES_BY_CATEGORY: dict[str, list] = {}
for _r in _POSITIVES:
    _POSITIVES_BY_CATEGORY.setdefault(_r.category or "unknown", []).append(_r)

_GATED_CATEGORIES = sorted(
    cat for cat, recs in _POSITIVES_BY_CATEGORY.items()
    if len(recs) >= _CATEGORY_MIN_POSITIVES
)


@pytest.mark.skipif(
    not _AVAILABLE,
    reason="CredData corpus not on disk — category blind-spot gate cannot run")
@pytest.mark.parametrize("category", _GATED_CATEGORIES)
def test_creddata_category_is_not_entirely_blind(category, scan_result):
    recs = _POSITIVES_BY_CATEGORY[category]
    recalled = sum(1 for r in recs if r.id in scan_result)
    assert recalled > 0, (
        f"keyhog recalled ZERO of {len(recs)} human-reviewed CredData "
        f"{category!r} secrets — the shipped scanner is wholly blind to this "
        f"credential class, not just missing hard individuals. This is a "
        f"detector-coverage finding, not a tuning miss.")


# ── recall-floor ratchet (the aggregate regression guard) ─────────────
# The single number a recall regression hides inside. Pinned to the measured
# recall on 2026-06-15 (the simd/deterministic backend). It is a RATCHET: when
# recall improves, RAISE this floor in the same commit so the gain can never
# silently regress away. CI fails the moment a change drops a previously-found
# secret below the line. This is what makes "recall quietly fell from 2504 to
# 2490" impossible to merge.
_RECALL_FLOOR = 2504

@pytest.mark.skipif(not _AVAILABLE, reason="CredData corpus not on disk — recall floor cannot run")
def test_creddata_recall_does_not_regress_below_floor(scan_result):
    recalled = len(scan_result)
    assert recalled >= _RECALL_FLOOR, (
        f"CredData recall REGRESSED: {recalled} secrets recalled, floor is "
        f"{_RECALL_FLOOR} (of {len(_POSITIVES)} positives). A change dropped "
        f"{_RECALL_FLOOR - recalled} previously-found real secret(s). Fix the "
        f"candidate/suppression regression; do not weaken the floor to make this "
        f"run green.")
    if recalled > _RECALL_FLOOR:
        print(f"\nNOTE: recall improved to {recalled} (floor {_RECALL_FLOOR}). "
              f"Raise _RECALL_FLOOR to {recalled} to lock in the gain.")
