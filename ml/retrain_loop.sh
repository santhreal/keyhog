#!/usr/bin/env bash
# The keyhog ML feedback loop, in one command: harvest the real distribution →
# blend with the synthetic corpus → retrain → validate on a leakage-free real
# held-out → (optionally) ship weights.bin behind recall-first gates.
#
# Why this exists: the MoE is only as good as the distribution it trains on. The
# synthetic-only model scored real ambiguous secrets ~0.02; feeding it the real
# candidates keyhog actually surfaces (labelled by ground truth) recovered real
# held-out recall from ~0 to 0.76 and made the entropy→MoE unification a
# recall-safe precision win. Run this each dogfood round so real FPs/FNs flow
# back into the model. See ml/README.md and the plan in this repo.
#
# Usage:
#   ml/retrain_loop.sh                      # measure only (writes a scratch model)
#   ml/retrain_loop.sh --write              # ship weights.bin if gates pass (+.bak)
#   KEYHOG_BIN=/path/to/keyhog ml/retrain_loop.sh
#   CORPORA="creddata" ml/retrain_loop.sh   # which real corpora to harvest
#
# Gates (enforced by train_classifier.py; --write refuses on any miss):
#   * synthetic held-out F1   >= --min-f1            (breadth must not regress)
#   * real held-out recall@.40 >= --min-real-recall  (real recall must not regress)
set -euo pipefail

ML_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${ML_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

CORPORA="${CORPORA:-creddata}"
REAL_OUT="${REAL_OUT:-ml/data/real_corpus.jsonl}"
SYN_CORPUS="${SYN_CORPUS:-ml/data/corpus.jsonl}"
FEATURES="${FEATURES:-42}"
WRITE_ARGS=()
for a in "$@"; do
  WRITE_ARGS+=("$a")  # pass through --write / --min-f1 / --min-real-recall / etc.
done

# 1) Resolve a keyhog binary to harvest with (KEYHOG_BIN wins; else freshly built).
KEYHOG_BIN="${KEYHOG_BIN:-}"
if [[ -z "${KEYHOG_BIN}" ]]; then
  for c in \
      "${CARGO_TARGET_DIR:-target}/release-fast/keyhog" \
      "${CARGO_TARGET_DIR:-target}/release/keyhog" \
      "$(command -v keyhog || true)"; do
    [[ -n "${c}" && -x "${c}" ]] && { KEYHOG_BIN="${c}"; break; }
  done
fi
[[ -n "${KEYHOG_BIN}" ]] || { echo "error: no keyhog binary; set KEYHOG_BIN=" >&2; exit 2; }
echo "→ keyhog: ${KEYHOG_BIN}"

# 2) Harvest the real distribution (labels via the bench's ground-truth overlap).
echo "→ harvesting real corpus: ${CORPORA}"
python3 ml/harvest_corpus.py --corpora ${CORPORA} --keyhog-bin "${KEYHOG_BIN}" --out "${REAL_OUT}"

# 3) Retrain blended + validate on the leakage-free real held-out. The synthetic
#    F1 and real-recall gates live in train_classifier.py; without --write it
#    writes a scratch model and never touches the crate.
echo "→ retraining (synthetic + real, file-grouped held-out)"
python3 ml/train_classifier.py \
    --corpus "${SYN_CORPUS}" \
    --real-corpus "${REAL_OUT}" \
    --features "${FEATURES}" \
    "${WRITE_ARGS[@]}"

echo "✓ loop complete. Re-run with --write to ship weights.bin once the gates pass."
