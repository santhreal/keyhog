"""CredData competitor-recall TARGET-SPEC worklist, keyhog must lead EVERY
competitor on recall, overall AND per credential shape-class.

Distinct from the other CredData recall modules in this directory, all of which
grade keyhog against an *absolute* number:

* ``test_creddata_recall_floor_ratchet`` / ``test_creddata_recall_matrix`` pin a
  measured floor keyhog already clears (GREEN regression guards).
* ``test_recall_targets`` pins fixed product floors (0.90 overall, per-class)
  that are RED until generation lands.

This module grades keyhog against a *moving* yardstick: the BEST competitor's
recall on the SAME corpus, measured live in the same session. The product claim
is not "keyhog reaches 0.90", it is "keyhog beats trufflehog, noseyparker,
kingfisher, betterleaks, and titus on recall, on every credential class an
operator cares about". A class where ANY competitor recalls more real CredData
secrets than keyhog is a RED finding naming that competitor, that class, the two
recall fractions, and the gap (the recall worklist to overtake them all).

Why a separate, competitor-relative spec (Law 6, the worklist):

* The absolute floors can be GREEN while a competitor still beats keyhog on a
  class (e.g. keyhog ``hex-other`` 0.064 clears no stated floor, but kingfisher
  0.161 and noseyparker 0.138 both beat it: a real, named recall loss the
  absolute specs never surface).
* The yardstick self-updates: when a competitor regresses or keyhog improves,
  the verdict moves without editing a hardcoded competitor number, there is
  ONE source of truth (the live scan), never a stale pinned table that drifts
  from what the scanners actually do today (Adversarial vector 10, coherence).

Truth rule parity: every scanner is scored through the SAME ``score.overlap`` /
``found_record_ids`` containment rule and the SAME ``CredDataCorpus`` value
slicing the leaderboard uses, so "keyhog recalled fewer than kingfisher on
hex-other" here is bit-identical to the leaderboard's per-record attribution 
not a second, drifting yardstick.

The shape classifier is the SAME ``_shape_class`` rule ``test_recall_targets``
uses (re-imported, not re-defined) so a class named here is the exact pool the
absolute spec and the surfacing work are graded on, no third definition of
"what a hex64 secret is" (NO DUPLICATION).

LOUD on absence (never a silent green, Law 10):

* CredData corpus absent (``make creddata``) -> the whole module skips with that
  reason.
* No keyhog binary -> the keyhog scan fixture FAILS LOUD (a missing binary must
  never read as "keyhog beat everyone" nor as "keyhog lost to everyone").
* A competitor binary absent -> that competitor is reported UNAVAILABLE and the
  comparison against it is skipped LOUD (its row says why); keyhog is NOT
  silently credited a win it never earned against a scanner that never ran.
  ``KEYHOG_REQUIRE_COMPETITORS`` (comma list, or ``all``) turns a missing
  required competitor into a hard FAIL so a CI lane cannot pass this spec by
  simply not installing the competition.

Each comparison runs every scanner ONCE per session (heavy: full ~11k-file
CredData scan per scanner), this is a recall-gate / nightly target spec, not a
fast unit test. The keyhog and competitor scans are shared session fixtures so
the matrix pays one scan per scanner total.
"""

from __future__ import annotations

import os

import pytest

pytestmark = pytest.mark.target_spec

from bench.corpora.creddata import CredDataCorpus
from bench.scanners import resolve_scanner
from bench.scanners.keyhog import KeyhogScanner, resolve_keyhog_binary
from bench.schema import ScannerConfig
from bench.score import found_record_ids, score
# Reuse the SAME shape classifier + keyword anchor the absolute recall target
# spec uses (one definition of every miss class, never a drifting twin).
from bench.tests.test_recall_targets import (
    _BY_SHAPE,
    _KEYWORD_ANCHORED,
    _POSITIVES,
)

# ── corpus + competitor roster (collection time) ──────────────────────

_CORPUS = CredDataCorpus()
_AVAILABLE = _CORPUS.is_downloaded()
_RECORDS = _CORPUS.records() if _AVAILABLE else []

# Every competitor the leaderboard knows. keyhog is the subject, not a rival.
_COMPETITORS = ("trufflehog", "noseyparker", "kingfisher", "betterleaks", "titus")

# Shape classes graded for competitor leadership, each with the minimum pool
# size below which the class is too small to be a meaningful recall target on
# this corpus pin (mirrors the min_pool guard in test_recall_targets). UUID is
# excluded because the pinned UUID labels are identifiers, not credentials;
# rewarding scanners for flagging them would invert the precision contract.
_SHAPE_CLASSES: tuple[tuple[str, int], ...] = (
    ("hex64", 50),
    ("hex-other", 50),
    ("base64", 50),
    ("jwt", 20),
)

_KEYHOG_CFG = ScannerConfig(backend="simd", cache="off", daemon="off", mode="full")


def _required_competitors() -> set[str]:
    """Competitors a missing binary must turn into a hard FAIL (not a skip).

    Default: none required (a competitor not installed on this host is reported
    UNAVAILABLE and skipped LOUD). ``KEYHOG_REQUIRE_COMPETITORS=all`` requires
    every known competitor; a comma list requires exactly those names. This is
    the knob a CI recall lane sets so the spec cannot pass by simply omitting
    the competition."""
    raw = os.environ.get("KEYHOG_REQUIRE_COMPETITORS", "").strip()
    if not raw:
        return set()
    if raw.lower() == "all":
        return set(_COMPETITORS)
    return {s.strip() for s in raw.split(",") if s.strip()}


# ── one scan per scanner, shared across the whole matrix ───────────────


def _recalled_ids_for(findings) -> set[str]:
    """The positive-record-id hit-set for a scanner's findings, with the
    coherence check that it equals the canonical scorer's TP (so a per-class
    verdict here is bit-identical to the leaderboard's attribution)."""
    found = found_record_ids(_RECORDS, findings, _CORPUS.file_root)
    tp = score(_RECORDS, findings, _CORPUS.file_root).overall.tp
    assert len(found) == tp, (
        f"recall hit-set ({len(found)}) disagrees with the canonical scorer's "
        f"TP ({tp}), found_record_ids drifted from score(); fix before trusting "
        f"any competitor verdict")
    return found


@pytest.fixture(scope="session")
def keyhog_recalled():
    """keyhog's CredData recall hit-set (one scan). Zero findings or a missing
    binary is a harness failure that fails LOUD, it must never read as keyhog
    winning or losing every class off a binary that never ran."""
    binary = resolve_keyhog_binary()
    if binary is None:
        pytest.fail(
            "no keyhog binary found (set KEYHOG_BIN, or build a release binary "
            "with `cargo build --release`); refusing to grade keyhog vs every "
            "competitor off a binary that never ran")
    findings, _stats = KeyhogScanner(binary=binary).run(_CORPUS.scan_root, _KEYHOG_CFG)
    if not findings:
        pytest.fail(
            f"keyhog ({binary}) produced ZERO findings over CredData, a harness "
            f"failure (wrong binary / corpus path / scan error), not a recall "
            f"result. scan_root={_CORPUS.scan_root}")
    return _recalled_ids_for(findings)


@pytest.fixture(scope="session")
def competitor_recalled():
    """Map ``competitor name -> recall hit-set`` (or ``None`` if the binary is
    unavailable / errored). One scan per competitor, cached for the whole
    matrix. A required competitor (``KEYHOG_REQUIRE_COMPETITORS``) whose binary
    is missing fails LOUD here rather than being silently skipped downstream."""
    required = _required_competitors()
    out: dict[str, set[str] | None] = {}
    for name in _COMPETITORS:
        scanner = resolve_scanner(name)
        if not scanner.available():
            if name in required:
                pytest.fail(
                    f"required competitor {name!r} binary not found "
                    f"({scanner.binary}); KEYHOG_REQUIRE_COMPETITORS demands it "
                    f"produce a real result, refusing to credit keyhog a win it "
                    f"never earned against a scanner that never ran")
            out[name] = None
            continue
        try:
            findings, _stats = scanner.run(_CORPUS.scan_root, scanner.default_config())
        except Exception as exc:  # noqa: BLE001 - record LOUD, never a silent win
            if name in required:
                pytest.fail(
                    f"required competitor {name!r} errored: "
                    f"{type(exc).__name__}: {exc}")
            out[name] = None
            continue
        out[name] = _recalled_ids_for(findings)
    return out


def _recall(recalled: set[str], ids: list[str]) -> tuple[int, int, float]:
    hit = sum(1 for rid in ids if rid in recalled)
    total = len(ids)
    return hit, total, (hit / total if total else 0.0)


# ── TARGET 1: keyhog overall recall leads EVERY competitor ─────────────


@pytest.mark.skipif(
    not _AVAILABLE,
    reason="CredData corpus not on disk (benchmarks/corpora/creddata/CredData; "
           "run `make creddata`), competitor recall targets cannot be scored")
@pytest.mark.parametrize("competitor", _COMPETITORS)
def test_keyhog_overall_recall_leads_competitor(
        competitor, keyhog_recalled, competitor_recalled):
    """keyhog's OVERALL CredData recall must be >= this competitor's. A
    competitor that recalls more real positives than keyhog overall is a
    headline recall loss naming exactly who leads and by how much."""
    rival = competitor_recalled[competitor]
    if rival is None:
        pytest.skip(
            f"{competitor} binary unavailable on this host, overall-recall "
            f"comparison skipped LOUD (keyhog NOT credited a win it never "
            f"earned). Set KEYHOG_REQUIRE_COMPETITORS to make this a hard fail.")
    total = len(_POSITIVES)
    kh = len(keyhog_recalled)
    cr = len(rival)
    kh_r = kh / total if total else 0.0
    cr_r = cr / total if total else 0.0
    assert kh_r >= cr_r, (
        f"keyhog OVERALL CredData recall {kh_r:.4f} ({kh}/{total}) is BELOW "
        f"{competitor} {cr_r:.4f} ({cr}/{total}): {competitor} surfaces "
        f"{cr - kh} more real, human-reviewed credentials than keyhog. keyhog "
        f"must lead every competitor on recall; RED until it overtakes "
        f"{competitor} (do NOT weaken. Law 9).")


# ── TARGET 2: keyhog per-shape-class recall leads EVERY competitor ─────


@pytest.mark.skipif(
    not _AVAILABLE,
    reason="CredData corpus not on disk, per-class competitor recall cannot run")
@pytest.mark.parametrize(
    "competitor,klass,min_pool",
    [(c, k, p) for c in _COMPETITORS for (k, p) in _SHAPE_CLASSES],
    ids=[f"{c}:{k}" for c in _COMPETITORS for (k, _p) in _SHAPE_CLASSES],
)
def test_keyhog_class_recall_leads_competitor(
        competitor, klass, min_pool, keyhog_recalled, competitor_recalled):
    """keyhog's recall on this credential SHAPE class must be >= this
    competitor's. The overall number averages away which shapes keyhog is
    beaten on; this names each (competitor, class) where a rival surfaces more
    real secrets of that shape, the precise per-class recall worklist."""
    recs = _BY_SHAPE.get(klass, [])
    assert len(recs) >= min_pool, (
        f"shape class {klass!r} has only {len(recs)} value-anchored positives "
        f"on this CredData pin (< {min_pool}); too small to grade as a recall "
        f"target, re-bucket or bump the pin, do not silently pass.")
    rival = competitor_recalled[competitor]
    if rival is None:
        pytest.skip(
            f"{competitor} binary unavailable: {klass!r} comparison skipped "
            f"LOUD. Set KEYHOG_REQUIRE_COMPETITORS to make this a hard fail.")
    ids = [r.id for r in recs]
    kh_hit, total, kh_r = _recall(keyhog_recalled, ids)
    cr_hit, _total, cr_r = _recall(rival, ids)
    assert kh_r >= cr_r, (
        f"keyhog {klass!r} CredData recall {kh_r:.4f} ({kh_hit}/{total}) is "
        f"BELOW {competitor} {cr_r:.4f} ({cr_hit}/{total}): {competitor} "
        f"surfaces {cr_hit - kh_hit} more real {klass!r}-shaped secrets than "
        f"keyhog. This is a candidate-GENERATION gap on the {klass!r} shape: a "
        f"competitor catches it and keyhog does not. RED until keyhog's "
        f"{klass!r} generation overtakes {competitor} (Law 9, do not weaken).")


# ── TARGET 3: keyhog keyword-anchored recall leads EVERY competitor ────
# The cross-cutting "a human wrote `api_key = <value>` and a competitor caught
# it but keyhog did not" class (the most accountable single recall gap).


@pytest.mark.skipif(
    not _AVAILABLE,
    reason="CredData corpus not on disk, keyword-anchored competitor recall "
           "cannot run")
@pytest.mark.parametrize("competitor", _COMPETITORS)
def test_keyhog_keyword_anchored_recall_leads_competitor(
        competitor, keyhog_recalled, competitor_recalled):
    """keyhog's recall on keyword-anchored positives (a credential keyword left
    of the value on its line) must be >= this competitor's. These are the values
    an operator would most obviously call a secret; a competitor leading here is
    the clearest candidate-generation debt keyhog owes."""
    recs = _KEYWORD_ANCHORED
    assert len(recs) >= 100, (
        f"keyword-anchored pool is only {len(recs)} positives (< 100), too "
        f"small to grade; the keyword classifier or corpus pin changed.")
    rival = competitor_recalled[competitor]
    if rival is None:
        pytest.skip(
            f"{competitor} binary unavailable, keyword-anchored comparison "
            f"skipped LOUD. Set KEYHOG_REQUIRE_COMPETITORS to hard-fail.")
    ids = [r.id for r in recs]
    kh_hit, total, kh_r = _recall(keyhog_recalled, ids)
    cr_hit, _total, cr_r = _recall(rival, ids)
    assert kh_r >= cr_r, (
        f"keyhog KEYWORD-ANCHORED CredData recall {kh_r:.4f} ({kh_hit}/{total}) "
        f"is BELOW {competitor} {cr_r:.4f} ({cr_hit}/{total}). {competitor} "
        f"surfaces {cr_hit - kh_hit} more values written directly behind a "
        f"credential keyword than keyhog. That is the clearest candidate-"
        f"generation gap; RED until keyhog overtakes {competitor} (Law 9).")
