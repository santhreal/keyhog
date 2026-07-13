#!/usr/bin/env python3
"""Go/no-go probe for unifying entropy-fallback scoring onto the MoE.

Reconstructs the SHIPPED model (crates/scanner/src/weights.bin) forward pass in
numpy: byte-identical layout to ml_weights.rs / train_classifier.serialize 
and scores a battery of (a) real high-entropy SECRETS and (b) structured
high-entropy NON-secrets, using the Rust serve-path feature extractor.

If the shipped model scores the TP cluster well above the FP cluster, routing
the entropy fallback through the MoE will suppress entropy FPs while preserving
real recall. If the clusters overlap, the model needs corpus work first.

This probe scores the MODEL ONLY (no entropy heuristic, no shape gates), it is
the cleanest test of "can the model do the discrimination the entropy heuristic
currently can't".
"""
import struct
import sys
from pathlib import Path

import numpy as np

import config_lists
import rust_features

D = rust_features.NUM_FEATURES  # 42
EXPERT_COUNT, FC1, FC2 = 6, 32, 16
WEIGHTS = Path(__file__).resolve().parents[1] / "crates/scanner/src/weights.bin"


def load_weights(path):
    raw = open(path, "rb").read()
    flat = np.frombuffer(raw, dtype="<f4")
    expected = D * EXPERT_COUNT + EXPERT_COUNT + EXPERT_COUNT * (
        D * FC1 + FC1 + FC1 * FC2 + FC2 + FC2 + 1
    )
    assert flat.size == expected, f"{flat.size} != {expected}"
    off = 0

    def take(n):
        nonlocal off
        v = flat[off:off + n]
        off += n
        return v

    gate_w = take(D * EXPERT_COUNT).reshape(EXPERT_COUNT, D)
    gate_b = take(EXPERT_COUNT)
    experts = []
    for _ in range(EXPERT_COUNT):
        fc1w = take(FC1 * D).reshape(FC1, D)
        fc1b = take(FC1)
        fc2w = take(FC2 * FC1).reshape(FC2, FC1)
        fc2b = take(FC2)
        fc3w = take(1 * FC2).reshape(1, FC2)
        fc3b = take(1)
        experts.append((fc1w, fc1b, fc2w, fc2b, fc3w, fc3b))
    assert off == flat.size
    return gate_w, gate_b, experts


def fast_sigmoid(x):
    return 0.5 + 0.5 * x / (1.0 + abs(x))


def forward(x, gate_w, gate_b, experts):
    gl = gate_w @ x + gate_b
    gl = gl - gl.max()
    gp = np.exp(gl)
    gp = gp / gp.sum()
    logits = np.empty(EXPERT_COUNT, dtype=np.float64)
    for e, (fc1w, fc1b, fc2w, fc2b, fc3w, fc3b) in enumerate(experts):
        h = np.maximum(fc1w @ x + fc1b, 0.0)
        h = np.maximum(fc2w @ h + fc2b, 0.0)
        logits[e] = (fc3w @ h + fc3b)[0]
    return float(fast_sigmoid((gp * logits).sum()))


def feature_vectors(cases):
    kp, sk, tk, pk = config_lists.DEFAULT_LISTS
    records = [{"text": text, "context": context} for text, context in cases]
    return rust_features.compute_feature_matrix(records, (kp, sk, tk, pk), D).astype(np.float64)


# Real high-entropy SECRETS that reach the entropy fallback (expect HIGH).
TP = [
    ("wJalrXUtnFEMI7K8MDfNGbPxRziCY3p9qLm2vK4", 'aws_secret_access_key = "'),
    ("xK9mPq2vL8nR4wT6yU3zA1bC5dE7fG0hJ2kM4nP", "client_secret: "),
    ("Atr0xK9mPq2vL8nR4wT6yU3zHc1bC5dE7fG", 'password = "'),
    ("4eC39HqLyjWDarjtT1zdp7dcQm8nZx2vL5", 'secret_key = "'),
    ("aB3xY7zQ9mK2pL5nR8wT6vU1jH4kM0nP7qR", 'api_secret: "'),
    ("R8wT6vU1jH4kM0nP7qZx2vL5nDe9fG3hJ6k", 'token = "'),
]

# Structured / public high-entropy NON-secrets (expect LOW). Several of these
# the entropy fallback already shape-gates; the model scoring them low means it
# can subsume that work and catch the residual the gates miss.
FP = [
    ("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", "image: nginx@sha256:"),
    ("d41d8cd98f00b204e9800998ecf8427e", 'etag = "'),
    ("550e8400-e29b-41d4-a716-446655440000", 'request_id = "'),
    ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", "jwt_header = "),
    ("a3f5c8e1b9d7f2a6c4e8b1d5f9a2c6e4b8d1f5a9", 'commit = "'),
    ("com.fasterxml.jackson.databind.ObjectMapper", "class = "),
    ("application/vnd.github.v3+json", "accept = "),
    ("0123456789abcdef0123456789abcdef", 'build_id = "'),
]


def main():
    model = load_weights(WEIGHTS)
    tp_vectors = feature_vectors(TP)
    fp_vectors = feature_vectors(FP)
    print(f"shipped model: D={D}, {EXPERT_COUNT} experts\n")
    tp_scores, fp_scores = [], []
    print("== TP (real secrets, want HIGH) ==")
    for (t, _c), vec in zip(TP, tp_vectors):
        s = forward(vec, *model)
        tp_scores.append(s)
        print(f"  {s:.3f}  {t[:42]}")
    print("\n== FP (structured non-secrets, want LOW) ==")
    for (t, _c), vec in zip(FP, fp_vectors):
        s = forward(vec, *model)
        fp_scores.append(s)
        print(f"  {s:.3f}  {t[:42]}")
    tp = np.array(tp_scores)
    fp = np.array(fp_scores)
    print(f"\nTP  min={tp.min():.3f} mean={tp.mean():.3f} max={tp.max():.3f}")
    print(f"FP  min={fp.min():.3f} mean={fp.mean():.3f} max={fp.max():.3f}")
    print(f"separation (TP.min - FP.max) = {tp.min() - fp.max():+.3f}")
    # A clean separator exists if some threshold puts all TP above all FP.
    print(f"VERDICT: {'CLEAN SEPARATION' if tp.min() > fp.max() else 'OVERLAP, model needs corpus work'}")


if __name__ == "__main__":
    sys.exit(main())
