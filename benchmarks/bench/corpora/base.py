"""Corpus contract: a labeled (or perf-only) set of on-disk fixtures.

A :class:`Corpus` exposes three things the runner needs:

* ``root`` — the single directory handed to a scanner; it recurses and pays
  one cold-start over the whole tree (the 257x amortisation score.py
  documents).
* ``records()`` — the ground truth as :class:`LabeledRecord` objects. Empty
  for a perf-only corpus (kernel).
* ``info()`` — fixture count / labeled-positive count / total bytes for the
  result header.

One record == one labeled credential candidate. A file may carry several
records (CredData has multiple secrets per file); the scorer groups by file
so multi-secret attribution is correct, while the single-record-per-file
mirror still scores identically.
"""

from __future__ import annotations

import pathlib
from abc import ABC, abstractmethod
from dataclasses import dataclass

from ..schema import CorpusInfo


@dataclass
class LabeledRecord:
    """One ground-truth credential candidate.

    ``label`` follows the SecretBench convention: ``True`` = confirmed real
    secret (a positive the scanner MUST surface), ``False`` = confirmed
    non-secret (a negative the scanner must NOT fire on). ``ignore=True``
    marks a candidate that scores neither way (CredData's ``Template`` /
    ``X`` rows, placeholders) — findings overlapping it are dropped, and it
    never contributes a false negative.
    """

    id: str
    secret: str
    label: bool
    category: str
    file_path: str          # relative to the corpus file_root
    line_start: int = 0
    line_end: int = 0
    ignore: bool = False


class Corpus(ABC):
    """Adapter from an on-disk dataset to (root, records, info)."""

    #: short stable identifier used in result filenames + reports
    name: str = ""

    @property
    @abstractmethod
    def root(self) -> pathlib.Path:
        """Directory a scanner is pointed at (recurses)."""

    @property
    def file_root(self) -> pathlib.Path:
        """Prefix under which a record's ``file_path`` resolves. Defaults to
        ``root``; CredData overrides it (manifest dir != data dir)."""
        return self.root

    @abstractmethod
    def records(self) -> list[LabeledRecord]:
        """Ground-truth records. Empty list for a perf-only corpus."""

    def is_labeled(self) -> bool:
        return bool(self.records())

    def info(self) -> CorpusInfo:
        recs = self.records()
        positives = sum(1 for r in recs if r.label and not r.ignore)
        total_bytes = self._tree_bytes()
        return CorpusInfo(
            name=self.name,
            fixture_count=len(recs) if recs else self._tree_file_count(),
            labeled_positives=positives,
            bytes=total_bytes,
        )

    # ── size probes (best-effort; never raise) ────────────────────────

    def _tree_bytes(self) -> int:
        total = 0
        root = self.root
        if not root.exists():
            return 0
        for p in root.rglob("*"):
            try:
                if p.is_file():
                    total += p.stat().st_size
            except OSError:
                continue
        return total

    def _tree_file_count(self) -> int:
        root = self.root
        if not root.exists():
            return 0
        n = 0
        for p in root.rglob("*"):
            try:
                if p.is_file():
                    n += 1
            except OSError:
                continue
        return n


def resolve_corpus(name: str, **kw) -> Corpus:
    """Factory: map a corpus name to its adapter. Kept here (not in each
    module) so the runner/report import one symbol and new corpora register
    by adding a branch. Imports are lazy so a missing optional dep in one
    adapter never breaks the others."""
    name = name.lower()
    if name == "mirror":
        from .mirror import MirrorCorpus
        return MirrorCorpus(**kw)
    if name in ("homefield-betterleaks", "homefield_betterleaks", "betterleaks-homefield"):
        from .homefield import HomefieldCorpus
        return HomefieldCorpus(turf="betterleaks", **kw)
    if name in ("homefield-kingfisher", "homefield_kingfisher", "kingfisher-homefield"):
        from .homefield import HomefieldCorpus
        return HomefieldCorpus(turf="kingfisher", **kw)
    if name == "creddata":
        from .creddata import CredDataCorpus
        return CredDataCorpus(**kw)
    if name == "kernel":
        from .perf_corpus import KernelCorpus
        return KernelCorpus(**kw)
    raise SystemExit(
        f"unknown corpus {name!r}; known: mirror, homefield-betterleaks, "
        f"homefield-kingfisher, creddata, kernel"
    )
