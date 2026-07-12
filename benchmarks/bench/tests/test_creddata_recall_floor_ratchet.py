"""Aggregate CredData recall FLOOR ratchet (TESTING vector 12, lane 9).

The per-secret matrix (``test_creddata_recall_matrix``) names each individual
miss, and the per-category gate names a class keyhog is *wholly* blind to.
Neither catches a UNIFORM sag: a detection change that drops, say, 10 % of the
positives in *every* category at once never zeroes a category and never (for
most secrets) flips a specific previously-found one — yet the overall recall
falls. This module pins the single aggregate number with a hard floor, so a
broad regression that the granular gates average away still turns the suite red.

This is a RATCHET, not a target: the floor sits safely BELOW the current
measured recall (keyhog is recall-bound on real CredData — a candidate-
GENERATION gap, ~18 % measured today), so it goes red only on a real LOSS, not
on noise. Raise ``_DEFAULT_FLOOR`` when recall improves durably so the gate
locks in the gain; never lower it to make a regression pass (Law 9). The floor
is overridable via ``KEYHOG_CREDDATA_RECALL_FLOOR`` for local experiments, but
CI uses the committed default.

Requirements, both LOUD on absence (never a silent green, Law 10):
  * the CredData corpus on disk (``benchmarks/corpora/creddata/CredData``;
    ``make creddata``) — absent => the module skips with that exact reason.
  * a built keyhog binary (``KEYHOG_BIN`` or a release binary) — absent => the
    scan fixture FAILS LOUDLY (a missing binary is a harness error, never a
    misleading 0.0 recall).

The scan + scoring reuse the SAME adapter, ``score`` truth rule, and ``simd``
backend the leaderboard and the per-secret matrix use, so this floor and those
per-secret verdicts can never disagree about what was found.
"""

from __future__ import annotations

import os

import pytest

from bench.corpora.creddata import CredDataCorpus
from bench.score import score

# ── corpus load (collection time) ─────────────────────────────────────

_CORPUS = CredDataCorpus()
_AVAILABLE = _CORPUS.is_downloaded()
_RECORDS = _CORPUS.records() if _AVAILABLE else []

# The committed floor. keyhog's measured CredData recall is ~0.18 today; this
# floor sits below it so only a genuine regression trips it. Bump it (never
# below the prior committed value) when a recall win lands durably.
_DEFAULT_FLOOR = 0.12


def _floor() -> float:
    raw = os.environ.get("KEYHOG_CREDDATA_RECALL_FLOOR")
    if raw is None:
        return _DEFAULT_FLOOR
    try:
        return float(raw)
    except ValueError:
        pytest.fail(
            f"KEYHOG_CREDDATA_RECALL_FLOOR={raw!r} is not a float — refusing to "
            f"run the ratchet against an unparseable floor")


# ── one scan, scored once ─────────────────────────────────────────────


@pytest.fixture(scope="session")
def detection(creddata_simd_findings):
    """Run keyhog ONCE over CredData and return the scored ``Detection``. A
    missing binary or a zero-finding scan is a harness failure that fails LOUD
    — it must never masquerade as a recall regression."""
    return score(_RECORDS, creddata_simd_findings, _CORPUS.file_root)


@pytest.mark.skipif(
    not _AVAILABLE,
    reason="CredData corpus not on disk (benchmarks/corpora/creddata/CredData; "
           "run `make creddata`) — aggregate recall floor cannot be scored")
def test_aggregate_creddata_recall_meets_floor(detection):
    floor = _floor()
    overall = detection.overall
    recall = overall.recall()
    total_positives = overall.tp + overall.fn

    # Sanity: there must be a meaningful number of ground-truth positives, or
    # the recall fraction is statistically meaningless (and a corpus-load bug
    # would make the floor pass vacuously at recall 0/0 == 0.0 -> caught below).
    assert total_positives >= 100, (
        f"CredData yielded only {total_positives} scored positives (<100) — the "
        f"corpus failed to load enough ground truth to ratchet recall against; "
        f"this is a harness/corpus error, not a recall result")

    assert recall >= floor, (
        f"aggregate CredData recall regressed: {recall:.4f} "
        f"({overall.tp}/{total_positives} positives) is BELOW the committed "
        f"floor {floor:.4f}. This is a broad recall LOSS the per-secret and "
        f"per-category gates can average away. If the drop is intentional, the "
        f"floor must NOT be lowered to hide it (Law 9) — fix the regression.")


@pytest.mark.skipif(
    not _AVAILABLE,
    reason="CredData corpus not on disk — recall headroom check cannot run")
def test_committed_floor_is_not_above_measured_recall(detection):
    """Coherence guard: the COMMITTED default floor must sit at or below the
    measured recall, so the ratchet is a real lower bound and not a target that
    is already failing. (Runs against the default, ignoring any env override.)"""
    overall = detection.overall
    recall = overall.recall()
    assert _DEFAULT_FLOOR <= recall + 1e-9, (
        f"the committed _DEFAULT_FLOOR ({_DEFAULT_FLOOR:.4f}) is ABOVE the "
        f"current measured recall ({recall:.4f}) — the ratchet would fail on a "
        f"clean tree. Either recall regressed, or the floor was raised past the "
        f"truth; reconcile before committing.")
