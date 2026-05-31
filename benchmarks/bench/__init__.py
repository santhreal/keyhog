"""keyhog benchmarking framework - reproducible benchmark contracts.

The package provides the common result schema, host capture, corpus adapters,
and SecretBench-compatible scoring used by the benchmark matrix.

Layout::

    bench.schema    common result contract (RunResult + nested records)
    bench.hardware  host capture (os/cpu/cores/ram/gpu)
    bench.score     overlap/attribution scorer (ported from score.py)
    bench.corpora   corpus adapters -> LabeledRecord stream

The package is import-safe with no heavy deps at module load: optional
dependencies (pyarrow for parquet corpora) are imported lazily inside the
functions that need them.
"""

from __future__ import annotations

SCHEMA_VERSION = "bench-v1"

__all__ = ["SCHEMA_VERSION"]
