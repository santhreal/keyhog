"""keyhog benchmarking framework - reproducible benchmark contracts.

The package provides the common result schema, host capture, corpus adapters,
and SecretBench-compatible scoring used by the benchmark matrix.

Layout::

    bench.schema    common result contract (RunResult + nested records)
    bench.hardware  host capture (os/cpu/cores/ram/gpu)
    bench.score     overlap/attribution scorer (ported from score.py)
    bench.corpora   corpus adapters -> LabeledRecord stream
    bench.profile_artifact  keyhog-profile v2 artifact reader + digest refs
    bench.profile_capture   paired control/candidate profiled runs
    bench.trials    cold/warm/steady trial runner with noise receipts
    bench.robust_stats      seeded bootstrap CIs, MAD outliers, effect sizes
    bench.profile_gates     overhead / stage / workflow-speed budgets
    bench.receipts  provenance-bound performance receipts
    bench.profile_matrix    nightly cross-device profiling matrix

The package is import-safe with no heavy deps at module load: optional
dependencies (pyarrow for parquet corpora) are imported lazily inside the
functions that need them.
"""

from __future__ import annotations

SCHEMA_VERSION = "bench-v4"
LEGACY_SCHEMA_VERSIONS = frozenset({"bench-v3"})

__all__ = ["LEGACY_SCHEMA_VERSIONS", "SCHEMA_VERSION"]
