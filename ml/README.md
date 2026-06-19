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

## The real-distribution feedback loop (harvest → retrain → gate)

The synthetic corpus (`corpus.py`) gives breadth but not the real distribution
keyhog is deployed against. A synthetic-only model scored real but shape-ambiguous
CredData secrets (lowercase-heavy tokens, digit-run ids, symbol-laden passwords)
near ~0.02 — it learned "junk-looking shape = non-secret" from synthetic
negatives. The
fix is to train on the real candidates keyhog actually surfaces, labelled by
ground truth:

```
ml/retrain_loop.sh            # measure only (scratch model, no crate change)
ml/retrain_loop.sh --write    # ship weights.bin if the gates pass (+.bak)
```

which runs:

1. **harvest** (`harvest_corpus.py`) — scan the real corpora (CredData) with
   keyhog, label each candidate via the bench's ground-truth overlap
   (`benchmarks/bench/score.py`), and emit `{text, context, label, kind}` where
   `context` is the byte-exact serve ml_context (`file:{path}\n{±5-line window}`).
2. **retrain** (`train_classifier.py --real-corpus`) — blend synthetic (random
   85/15) + real (split **by file**, never randomly — a repo's secrets must not
   span train/test) and report metrics on a leakage-free real held-out.
3. **gate** — `--write` refuses unless synthetic held-out F1 ≥ `--min-f1`, real
   held-out recall@0.40-floor ≥ `--min-real-recall`, and every positive-bearing
   real held-out class clears `--min-real-class-recall` without regressing versus
   the existing model card when class metrics are present. Aggregate recall is
   not allowed to hide a failed tail class.

Measured impact of one loop (CredData): real held-out recall@floor 0 → **0.76**,
synthetic F1 held at 0.96, and on the never-trained-on mirror corpus precision
held (0.994) with recall +0.7pt — i.e. it generalises, it did not overfit to
CredData. With the better model the entropy→MoE unification
(`entropy_ml_authoritative`, default on) flips from a recall regression into a
recall-safe precision win (CredData +1 TP / −127 FP). Run the loop each dogfood
round so real FPs/FNs keep flowing back into the model.

> Note: `ml/data/real_corpus.jsonl` and `benchmarks/results/` contain REAL
> secrets and are gitignored — never commit them.

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
| `rust_features.py` | training feature source; batches records through Rust `dump_features` |
| `feature_parity.py` | parity/debug port of `ml_features.rs` (not used for training features) |
| `config_lists.py` | serve-path detector keyword lists, mirror of `config.rs` |
| `corpus.py` | labeled training corpus generator (heavy base64-of-binary negatives) |
| `train_classifier.py` | trains the MoE, evaluates, serializes `weights.bin` and `model_card.json` |
| `parity_check.py` | asserts the Python debug port still matches the Rust serve-path extractor |

## Retraining

```bash
# 1. (one-time) build the feature-parity oracle and PROVE the Python port
#    matches the Rust serve path - a retrain is only valid if this passes.
cargo build -p keyhog-scanner --example dump_features
KEYHOG_DUMP_FEATURES=$(find "$CARGO_TARGET_DIR" -path '*examples/dump_features' -type f | head -1) \
  python3 ml/parity_check.py

# 2. generate the corpus
python3 ml/corpus.py --out ml/data/corpus.jsonl

# 3. harvest real candidates, then train + install. Training reads the same Rust
#    serve-path feature extractor via KEYHOG_DUMP_FEATURES, backs up the
#    existing weights.bin/model_card.json to .bak, and refuses to write unless
#    synthetic F1 plus aggregate and per-class leakage-free real held-out recall
#    clear the gates.
python3 ml/harvest_corpus.py --corpora "$CRED_CORPORA" \
  --keyhog-bin target/release/keyhog --out ml/data/real_corpus.jsonl
KEYHOG_DUMP_FEATURES=$(find "$CARGO_TARGET_DIR" -path '*examples/dump_features' -type f | head -1) \
  python3 ml/train_classifier.py --corpus ml/data/corpus.jsonl \
    --real-corpus ml/data/real_corpus.jsonl \
    --features 42 --compare --write --out crates/scanner/src/weights.bin \
    --model-card crates/scanner/src/model_card.json

# 4. rebuild and run the scanner ML tests against the new weights + card
cargo test -p keyhog-scanner ml_scorer
```

`crates/scanner/build.rs` validates that `model_card.json` names the exact
FNV-derived `weights.bin` model version before embedding both. A stale or
missing card fails the build instead of producing an `unknown` model lineage.

## Parity contract

Training features come from Rust `dump_features`, not a Python port; that keeps
the trainer and scanner on one extractor. `feature_parity.py` and
`decode_structure.py` remain debug/parity ports and must compute byte-identical
results to their Rust counterparts; `parity_check.py` enforces this across an
input battery (41/42 features). The one tolerated gap is the continuous entropy feature
(#4): the serve path uses an x86 SIMD entropy kernel that accumulates in f32
(~0.2% vs the exact f64 value), so feature #4 is checked to 5e-3 while the
entropy threshold features (#5,#6,#7) and every other feature are exact. A
mismatch anywhere else means the debug oracle is stale and blocks a retrain.
