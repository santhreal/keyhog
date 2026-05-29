# keyhog ML pipeline

Rebuilt training pipeline for the mixture-of-experts secret scorer embedded in
`crates/scanner/src/weights.bin` (loaded by `ml_weights.rs`, run by
`ml_scorer.rs`). It exists so the model can be **retrained** - the original
pipeline was lost, freezing the model. This one is reproducible end to end and
adds the decode-structure feature that lets the model filter base64-wrapped
binary.

## Why it matters (the base64 result)

keyhog already decodes candidates (`decode_structure.rs`: magic bytes +
protobuf-wire). Until now that signal never reached the model - all 41 ML
features were surface-level, so a base64 blob that decodes to a PNG looked like
a high-entropy secret. Feeding the decode verdict in as feature #41 changes
that. On the held-out split:

| model | F1 | precision | recall | base64-binary false-flag rate |
|-------|------|-----------|--------|-------------------------------|
| 41 features (no decode) | 0.924 | 0.895 | 0.955 | 18.2% (98/537) |
| 42 features (with decode) | **0.964** | **0.976** | 0.953 | **0.0% (0/537)** |

Recall holds; precision jumps; base64-of-binary false positives go to zero.

## Architecture (must match `ml_scorer.rs` exactly)

```
gate:   Linear(D, 6) -> softmax over 6 experts
expert: Linear(D, 32) -> ReLU -> Linear(32, 16) -> ReLU -> Linear(16, 1)
output: fast_sigmoid( sum_e softmax(gate)[e] * expert_logit_e )
D = 42
```

`fast_sigmoid(x) = 0.5 + 0.5*x/(1+|x|)` is the exact serve-time nonlinearity;
the trainer optimizes through it so trained probabilities are the ones the Rust
scanner produces. `weights.bin` layout (little-endian f32), matching the offsets
in `ml_weights.rs`:

```
gate.weight[6,D], gate.bias[6],
per expert e in 0..6:
  fc1.weight[32,D], fc1.bias[32], fc2.weight[16,32], fc2.bias[16],
  fc3.weight[1,16], fc3.bias[1]
```

`nn.Linear(in,out).weight` is `[out,in]` row-major, exactly the
`weights[out*in + in]` indexing the Rust forward pass uses, so flattening is a
direct copy.

## Files

| file | role |
|------|------|
| `decode_structure.py` | byte-exact port of `decode_structure.rs` (feature #41 + corpus oracle) |
| `features.py` | byte-exact port of `ml_features.rs` (the 42-dim feature vector) |
| `config_lists.py` | serve-path detector keyword lists, mirror of `config.rs` |
| `corpus.py` | labeled training corpus generator (heavy base64-of-binary negatives) |
| `train_classifier.py` | trains the MoE, evaluates, serializes `weights.bin` |
| `parity_check.py` | asserts `features.py` == the Rust serve-path extractor |

## Retraining

```bash
# 1. (one-time) build the feature-parity oracle and PROVE the Python port
#    matches the Rust serve path - a retrain is only valid if this passes.
cargo build -p keyhog-scanner --example dump_features
KEYHOG_DUMP_FEATURES=$(find "$CARGO_TARGET_DIR" -path '*examples/dump_features' -type f | head -1) \
  python3 ml/parity_check.py

# 2. generate the corpus
python3 ml/corpus.py --out ml/data/corpus.jsonl

# 3. train + install (backs up the existing weights.bin to .bak, refuses to
#    write if held-out F1 < --min-f1). --compare also reports the 41-feature
#    baseline on the same split.
python3 ml/train_classifier.py --corpus ml/data/corpus.jsonl \
    --features 42 --compare --write --out crates/scanner/src/weights.bin

# 4. rebuild and run the scanner ML tests against the new weights
cargo test -p keyhog-scanner ml_scorer
```

## Parity contract

`features.py` and `decode_structure.py` must compute byte-identical results to
their Rust counterparts; `parity_check.py` enforces this across an input battery
(41/42 features). The one tolerated gap is the continuous entropy feature
(#4): the serve path uses an x86 SIMD entropy kernel that accumulates in f32
(~0.2% vs the exact f64 value), so feature #4 is checked to 5e-3 while the
entropy threshold features (#5,#6,#7) and every other feature are exact. A
mismatch anywhere else is train/serve skew and blocks a retrain.
