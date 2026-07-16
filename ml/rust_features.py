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

import detector_policy

# Width of the CURRENT serve path (model_arch::INPUT_DIM). Legacy prefixes
# (41 = pre-decode-structure, 42 = pre-service-context, 43 = pre-detector
# conditioning, 51 = pre-entropy-family conditioning) remain requestable:
# features are strictly appended, so a narrower model is a column prefix.
NUM_FEATURES = 55

Lists = tuple[Sequence[str], Sequence[str], Sequence[str], Sequence[str]]


def _b64(value: str) -> str:
    if not value:
        return ""
    return base64.b64encode(value.encode("utf-8")).decode("ascii")


def encode_record(
    text: str,
    context: str,
    lists: Lists,
    detector_id: str,
    candidate_channel: str,
) -> str:
    if candidate_channel not in {"pattern", "entropy"}:
        raise ValueError(
            f"candidate_channel must be 'pattern' or 'entropy', got {candidate_channel!r}"
        )
    kp, sk, tk, pk = lists
    fields = [
        _b64(text),
        _b64(context),
        _b64("\n".join(kp)),
        _b64("\n".join(sk)),
        _b64("\n".join(tk)),
        _b64("\n".join(pk)),
        _b64(detector_id),
        _b64(candidate_channel),
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
    if num_features not in (41, 42, 43, 51, NUM_FEATURES):
        raise ValueError(
            f"unsupported feature width {num_features}; expected 41, 42, 43, 51 or {NUM_FEATURES}"
        )
    materialized = list(records)
    for idx, rec in enumerate(materialized):
        if not str(rec.get("text", "")):
            raise ValueError(
                f"record {idx} has empty text; dump_features requires non-empty text"
            )
    lines = []
    for idx, rec in enumerate(materialized):
        detector_id = str(rec.get("detector_id", "")).strip()
        candidate_channel = str(rec.get("candidate_channel", "")).strip()
        if not detector_id:
            raise ValueError(f"record {idx} omits detector_id")
        if not candidate_channel:
            raise ValueError(f"record {idx} omits candidate_channel")
        detector_policy.validate_candidate_channel(detector_id, candidate_channel)
        lines.append(
            encode_record(
                str(rec["text"]),
                str(rec["context"]),
                lists,
                detector_id,
                candidate_channel,
            )
        )
    rows = run_dump_features(lines)
    if not rows:
        return np.zeros((0, num_features), dtype=np.float32)
    matrix = np.asarray(rows, dtype=np.float32)
    if num_features == NUM_FEATURES:
        return matrix
    return matrix[:, :num_features]
