# keyhog ML pipeline

Rebuilt training pipeline for the mixture-of-experts secret scorer embedded in
`crates/scanner/src/weights.bin` (loaded by `ml_weights.rs`, run by
`ml_scorer.rs`). It exists so the model can be **retrained**: the original
pipeline was lost, freezing the model. This pipeline is reproducible end to end,
feeds decode structure into scoring, and conditions every serve-time feature
vector on the detector TOML and candidate channel that produced it.

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
near ~0.02; it learned "junk-looking shape = non-secret" from synthetic
negatives. The
fix is to train on the real candidates keyhog actually surfaces, labelled by
ground truth:

```
ml/retrain_loop.sh            # measure only (scratch model, no crate change)
ml/retrain_loop.sh --write --verify  # ship only after statistical, contract, and benchmark gates
```

Unless `KEYHOG_BIN=/path/to/keyhog` is set explicitly, `retrain_loop.sh`
rebuilds the current tree before harvesting so stale target/PATH binaries cannot
define the training distribution.

which runs:

1. **harvest** (`harvest_corpus.py`): scan the real corpora (CredData) with
   keyhog, label each candidate via the bench's ground-truth overlap
   (`benchmarks/bench/score.py`), and emit `{text, context, label, kind, class,
   detector_id, candidate_channel, source_file}` where `context` is the byte-exact serve ml_context
   (`file:{path}\n{±5-line window}`), `class` is the scorer category, and
   `detector_id` is the keyhog detector that fired.
2. **retrain** (`train_classifier.py --real-corpus`): blend synthetic (random
   85/15) + real (split **by file**, never randomly; a repo's secrets must not
   span train/test) and report metrics on a leakage-free real held-out.
3. **gate:** `--write` refuses unless synthetic held-out F1 ≥ `--min-f1`, real
   held-out F1/precision clear their floors, recall@0.40-floor ≥
   `--min-real-recall`, every positive-bearing
   held-out class reached through `blend` or `authoritative` policy clears its
   recall floor, and every such detector channel has positive and negative
   held-out support and clears its detector floor without regressing. A missing
   authoritative channel is a write failure, not a skipped metric. `lift`
   detectors remain visible in the card but cannot lose a
   structural finding, so their model-only recall does not block a write.
   Train-split detector and positive-class balancing raise underrepresented
   recall-sensitive loss without reading held-out labels and only for detector
   modes that can reduce recall.
   Canonical positive and negative probes are hard gates, not informational
   logging: a model that reverses a known secret/hash/placeholder/binary-blob
   contract is refused before serialization.

Measured impact of one loop (CredData): real held-out recall@floor 0 → **0.76**,
synthetic F1 held at 0.96, and on the never-trained-on mirror corpus precision
held (0.994) with recall +0.7pt (i.e. it generalises; it did not overfit to
CredData. With the better model the entropy→MoE unification
(`entropy_ml_authoritative`, default on) flips from a recall regression into a
recall-safe precision win (CredData +1 TP / −127 FP). Run the loop each dogfood
round so real FPs/FNs keep flowing back into the model.

The detector-conditioned 55-feature retrain on the current file-grouped split
improves the shipped model from F1 0.7806 / precision 0.7245 / recall-at-floor
0.8539 to F1 0.8324 / precision 0.7527 / recall-at-floor 0.9377. The four
authoritative entropy families reach 0.8784 (API key), 1.0 (generic), 0.9286
(password), and 0.9333 (token) recall at the report floor. These are model-card
held-out metrics. The generic family has only three held-out positives and zero
held-out negatives in the shipped card, so its 1.0 recall is not evidence of
precision. The stricter trainer now refuses another write until that channel
has both classes. Competitor and end-to-end scanner claims still require a
current-schema benchmark run.

> Note: `ml/data/real_corpus.jsonl` and `benchmarks/results/` contain REAL
> secrets and are gitignored; never commit them.

## Architecture (must match `ml_scorer.rs` exactly)

```
gate:   Linear(D, 6) -> softmax over 6 experts
expert: Linear(D, 32) -> ReLU -> Linear(32, 16) -> ReLU -> Linear(16, 1)
output: fast_sigmoid( sum_e softmax(gate)[e] * expert_logit_e )
D = 55
```

Features 43-54 condition the shared scorer on the active detector TOML and
candidate provenance: exact-service context, generic ownership, weak-anchor
status, verifier availability, required companions, structural password slots,
phase-2 ownership, pattern-versus-entropy channel, and a four-way entropy-family
one-hot read from the owning detector's `entropy_fallback.class`. Training
records must name both `detector_id` and `candidate_channel`; missing or unknown
owners, or a channel that disagrees with the finding identity, fail feature
extraction instead of producing an unconditioned score. The current weak-anchor
feature is detector-wide. Pattern-local weak-anchor policy is not fed to the
model because harvested findings do not yet carry exact matched-pattern
provenance; pretending otherwise would create train/serve skew.

The six-scanner differential is attached when current-schema benchmark results
exist. An unavailable differential is recorded explicitly on a candidate model;
`--require-differential` makes it a hard pre-write gate. The normal improvement
loop builds the candidate first and then benchmarks that exact binary, avoiding
a circular requirement for results from a model that could not yet be built.

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

The current trainer is CPU-resident and says so at startup. GPU work in this
pipeline is serve-time inference parity, not an implied CUDA training path.
It can also initialize from a compatible shipped artifact with
`--init-weights crates/scanner/src/weights.bin`. The binary layout is decoded
strictly and a feature-count mismatch fails before optimization. Warm-start
checkpoint selection will not accept a real-validation F1 or precision
regression relative to the initial artifact; `--epochs 0` with `--init-weights`
provides evaluation-only replay of that exact model.

## Files

| file | role |
|------|------|
| `decode_structure.py` | byte-exact port of `decode_structure.rs` (feature #41 + corpus oracle) |
| `rust_features.py` | training feature source; batches detector/channel-qualified records through Rust `dump_features` |
| `feature_parity.py` | parity/debug port of `ml_features.rs` (not used for training features) |
| `config_lists.py` | serve-path detector keyword lists, mirror of `config.rs` |
| `corpus.py` | labeled training corpus generator with positive coverage for every authoritative entropy family and heavy base64-of-binary negatives |
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

# 3. harvest real candidates, then train + install. Build the exact keyhog
#    binary that harvest receives; a stale scanner changes the training data.
#    Training reads the same Rust
#    serve-path feature extractor via KEYHOG_DUMP_FEATURES, backs up the
#    existing weights.bin/model_card.json to .bak, and refuses to write unless
#    synthetic F1 plus aggregate and per-class leakage-free real held-out recall
#    clear the gates.
cargo build --release -p keyhog --bin keyhog --features simd
python3 ml/harvest_corpus.py --corpora "$CRED_CORPORA" \
  --keyhog-bin "${CARGO_TARGET_DIR:-target}/release/keyhog" \
  --out ml/data/real_corpus.jsonl
KEYHOG_DUMP_FEATURES=$(find "$CARGO_TARGET_DIR" -path '*examples/dump_features' -type f | head -1) \
  python3 ml/train_classifier.py --corpus ml/data/corpus.jsonl \
    --real-corpus ml/data/real_corpus.jsonl \
    --features 55 --compare

# 4. Promote only through the verified loop. Direct trainer writes are refused.
ml/retrain_loop.sh --write --verify
```

`crates/scanner/build.rs` validates that `model_card.json` names the exact
FNV-derived `weights.bin` model version before embedding both. A stale or
missing card fails the build instead of producing an `unknown` model lineage.

## Parity contract

Training features come from Rust `dump_features`, not a Python port; that keeps
the trainer and scanner on one extractor. `feature_parity.py` and
`decode_structure.py` remain debug/parity ports and must compute byte-identical
results to their Rust counterparts; `parity_check.py` enforces this across an
input battery of all 55 features. The one tolerated gap is the continuous entropy feature
(#4): the serve path uses an x86 SIMD entropy kernel that accumulates in f32
(~0.2% vs the exact f64 value), so feature #4 is checked to 5e-3 while the
entropy threshold features (#5,#6,#7) and every other feature are exact. A
mismatch anywhere else means the debug oracle is stale and blocks a retrain.
