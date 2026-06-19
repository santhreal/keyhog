"""Rust serve-path feature extraction for the ML training pipeline.

The scanner owns feature extraction in
`crates/scanner/src/ml_scorer/ml_features.rs`. Training calls the
`dump_features` example through the same line protocol used by the parity gate
so retrained weights are built from serve-path features, not a second Python
implementation.
"""

from __future__ import annotations

import base64
import os
import subprocess
from pathlib import Path
from typing import Iterable, Mapping, Sequence

import numpy as np

NUM_FEATURES = 42

Lists = tuple[Sequence[str], Sequence[str], Sequence[str], Sequence[str]]


def _b64(value: str) -> str:
    if not value:
        return ""
    return base64.b64encode(value.encode("utf-8")).decode("ascii")


def encode_record(text: str, context: str, lists: Lists) -> str:
    kp, sk, tk, pk = lists
    fields = [
        _b64(text),
        _b64(context),
        _b64("\n".join(kp)),
        _b64("\n".join(sk)),
        _b64("\n".join(tk)),
        _b64("\n".join(pk)),
    ]
    return " ".join(fields)


def _dump_features_command() -> tuple[list[str], Path]:
    repo_root = Path(__file__).resolve().parents[1]
    binpath = os.environ.get("KEYHOG_DUMP_FEATURES")
    if binpath:
        return [binpath], repo_root
    return [
        "cargo",
        "run",
        "-q",
        "-p",
        "keyhog-scanner",
        "--example",
        "dump_features",
    ], repo_root


def run_dump_features(lines: Sequence[str]) -> list[list[float]]:
    if not lines:
        return []
    cmd, cwd = _dump_features_command()
    proc = subprocess.run(
        cmd,
        cwd=cwd,
        input=("\n".join(lines) + "\n").encode("utf-8"),
        capture_output=True,
    )
    if proc.returncode != 0:
        stderr = proc.stderr.decode("utf-8", "replace")
        raise RuntimeError(f"rust dump_features failed (exit {proc.returncode}):\n{stderr}")
    out = proc.stdout.decode("utf-8").strip().splitlines()
    rows = [[float(x) for x in line.split()] for line in out if line.strip()]
    if len(rows) != len(lines):
        raise RuntimeError(
            f"rust dump_features row count mismatch: got {len(rows)}, expected {len(lines)}"
        )
    for idx, row in enumerate(rows):
        if len(row) != NUM_FEATURES:
            raise RuntimeError(
                f"rust dump_features row {idx} width mismatch: got {len(row)}, "
                f"expected {NUM_FEATURES}"
            )
    return rows


def compute_feature_matrix(
    records: Iterable[Mapping[str, object]],
    lists: Lists,
    num_features: int,
) -> np.ndarray:
    if num_features not in (41, NUM_FEATURES):
        raise ValueError(
            f"unsupported feature width {num_features}; expected 41 or {NUM_FEATURES}"
        )
    materialized = list(records)
    for idx, rec in enumerate(materialized):
        if not str(rec.get("text", "")):
            raise ValueError(
                f"record {idx} has empty text; dump_features requires non-empty text"
            )
    lines = [encode_record(str(rec["text"]), str(rec["context"]), lists) for rec in materialized]
    rows = run_dump_features(lines)
    if not rows:
        return np.zeros((0, num_features), dtype=np.float32)
    matrix = np.asarray(rows, dtype=np.float32)
    if num_features == NUM_FEATURES:
        return matrix
    return matrix[:, :num_features]
