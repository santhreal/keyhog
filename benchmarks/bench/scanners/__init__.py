"""Scanner adapters.

Each adapter wraps a secret-scanner binary behind one contract
(:class:`bench.scanners.base.Scanner`): it reports its ``version()``, the
config ``variants()`` it supports, and a ``run(root, cfg)`` that returns
normalised findings plus a :class:`RunStats` (wall / peak-RSS / throughput).
A single scorer + runner then treats keyhog and every competitor
identically: the comparison stays apples-to-apples.
"""

from __future__ import annotations

from .base import RunStats, Scanner, resolve_scanner
from .competitors import (
    BetterleaksScanner,
    KingfisherScanner,
    NoseyparkerScanner,
    TitusScanner,
    TrufflehogScanner,
    _normalize_betterleaks,
    _normalize_kingfisher_jsonl,
    _normalize_nosey_report,
    _normalize_titus_datastore,
)
from .keyhog import KeyhogScanner, _normalize_keyhog

SCANNERS = {
    "keyhog": KeyhogScanner,
    "betterleaks": BetterleaksScanner,
    "kingfisher": KingfisherScanner,
    "noseyparker": NoseyparkerScanner,
    "trufflehog": TrufflehogScanner,
    "titus": TitusScanner,
}

# Canonical ordered scanner names, the single source the CLI defaults and the
# leaderboard/gate scanner lists derive from (never re-typed inline).
SCANNER_NAMES = tuple(SCANNERS)

__all__ = [
    "BetterleaksScanner",
    "KeyhogScanner",
    "KingfisherScanner",
    "NoseyparkerScanner",
    "RunStats",
    "SCANNERS",
    "SCANNER_NAMES",
    "Scanner",
    "TitusScanner",
    "TrufflehogScanner",
    "resolve_scanner",
]
