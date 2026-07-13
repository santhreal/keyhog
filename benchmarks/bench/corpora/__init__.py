"""Corpus adapters.

Every corpus, synthetic mirror, harvested home-turf, Samsung/CredData, the
Linux-kernel perf target, normalises to a stream of
:class:`bench.corpora.base.LabeledRecord` so a single scorer
(:mod:`bench.score`) serves them all. Perf-only corpora carry no labels and
are scored on speed/RSS alone.
"""

from __future__ import annotations

from .base import Corpus, LabeledRecord, resolve_corpus

__all__ = ["Corpus", "LabeledRecord", "resolve_corpus"]
