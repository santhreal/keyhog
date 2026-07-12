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

import json
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

    @property
    def scan_root(self) -> pathlib.Path:
        """The path a scanner is actually pointed at — the fixture tree with
        the ground-truth manifest/answer-key EXCLUDED. Defaults to ``root``;
        corpora whose manifest lives inside ``root`` override this to the
        manifest-free subtree (e.g. ``root/fixtures``).

        This is the fairness boundary: a scanner that reads the manifest
        would "find" every labeled secret in plaintext — measured on the 15k
        mirror, betterleaks fires 9392 spurious matches on ``manifest.jsonl``
        and kingfisher 7581. No scanner is ever shown the answer key, so the
        comparison reflects detection skill, not whether a tool happens to
        skip a data file keyhog already ignores."""
        return self.root

    @abstractmethod
    def _load_records(self) -> list[LabeledRecord]:
        """Parse the ground truth from disk. Empty list for a perf-only corpus.
        Called at most once per instance — :meth:`records` memoizes it."""

    def records(self) -> list[LabeledRecord]:
        """Ground-truth records, parsed once and cached on the instance.

        ``build_result`` -> ``info()`` -> ``records()`` plus ``score()`` and the
        ``__main__`` calibrate/analyze paths all ask for the same records several
        times per run; for CredData that is ~11k files re-opened and re-sliced.
        Memoising here parses each meta CSV exactly once."""
        cached = self.__dict__.get("_records_cache")
        if cached is None:
            cached = self._load_records()
            self._records_cache = cached
        return cached

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
    # Measured over scan_root (the manifest-free tree the scanner sees) so
    # throughput MB/s is bytes-actually-scanned and the answer key never
    # inflates the corpus size.

    def _tree_bytes(self) -> int:
        total = 0
        root = self.scan_root
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
        root = self.scan_root
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


def load_jsonl_manifest(path: pathlib.Path) -> list[LabeledRecord]:
    """Parse a SecretBench-shape ``manifest.jsonl`` into :class:`LabeledRecord`.

    Shared by the mirror and home-turf corpora (identical manifest shape and
    split layout), so the record mapping lives in ONE place. Callers own the
    manifest-missing error (each phrases its own regenerate hint)."""
    out: list[LabeledRecord] = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            r = json.loads(line)
            out.append(LabeledRecord(
                id=r["id"],
                secret=r.get("secret", ""),
                label=bool(r.get("label")),
                category=r.get("category", "unknown"),
                file_path=r.get("on_disk_path") or r.get("file_path", ""),
                line_start=int(r.get("start_line", 0) or 0),
                line_end=int(r.get("end_line", 0) or 0),
            ))
    return out


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
