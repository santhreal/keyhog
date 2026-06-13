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
#   ml/retrain_loop.sh --write              # ship weights.bin if train-gates pass (+.bak)
#   ml/retrain_loop.sh --write --verify     # ship, then REBUILD + per-detector FP gate;
#                                           #   auto-revert weights.bin on any regression
#   KEYHOG_BIN=/path/to/keyhog ml/retrain_loop.sh
#   CORPORA="creddata" ml/retrain_loop.sh   # which real corpora to harvest
#
# Train-time gates (enforced by train_classifier.py; --write refuses on any miss):
#   * synthetic held-out F1    >= --min-f1            (breadth must not regress)
#   * real held-out recall@.40 >= --min-real-recall  (real recall must not regress)
#
# Bench gate (--verify only; the guard the train-gates can't be): held-out F1 and
# recall passed last time too — the kubernetes-bootstrap-token +203-FP regression
# only showed up in the full per-detector CredData bench. --verify reproduces that
# bench against a self-captured baseline of the model being replaced and refuses
# (fail-closed: restores weights.bin from .bak + rebuilds) on any per-detector FP
# spike or overall-F1 regression. Without --verify, --write prints a loud banner
# that this guard has NOT run — it never silently ships an unverified model.
set -euo pipefail

ML_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${ML_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

CORPORA="${CORPORA:-creddata}"
REAL_OUT="${REAL_OUT:-ml/data/real_corpus.jsonl}"
SYN_CORPUS="${SYN_CORPUS:-ml/data/corpus.jsonl}"
FEATURES="${FEATURES:-42}"
WEIGHTS="${WEIGHTS:-crates/scanner/src/weights.bin}"
# Corpora the bench-verify gate runs on. mirror = the precision guardian, creddata
# = the real-distribution recall corpus where the prior regression surfaced.
VERIFY_CORPORA="${VERIFY_CORPORA:-mirror creddata}"
VERIFY_EPSILON="${VERIFY_EPSILON:-0.005}"
# Rebuild command for the bench-verify (weights.bin is include_bytes!-embedded, so
# a candidate model is only observable after a rebuild). Override for a different
# feature set / profile.
REBUILD_CMD="${REBUILD_CMD:-cargo build --release -p keyhog --bin keyhog --features simd}"

# Separate the loop's own --verify flag from the args forwarded to
# train_classifier.py (which does not know --verify). --write is detected so the
# verify stage only engages for a shipped model.
DO_VERIFY=0
DO_WRITE=0
WRITE_ARGS=()
for a in "$@"; do
  case "$a" in
    --verify) DO_VERIFY=1 ;;
    --write)  DO_WRITE=1; WRITE_ARGS+=("$a") ;;
    *)        WRITE_ARGS+=("$a") ;;  # --min-f1 / --min-real-recall / etc.
  esac
done
if [[ "${DO_VERIFY}" == "1" && "${DO_WRITE}" != "1" ]]; then
  echo "error: --verify requires --write (nothing is shipped to verify otherwise)" >&2
  exit 2
fi

# ── bench-verify helpers ────────────────────────────────────────────────────
# A leaderboard run for one corpus into a results dir, scored on the resolved
# keyhog binary (KEYHOG_NO_GPU=1 = the deterministic filesystem path the gate
# baselines were captured on). Run from benchmarks/ so `bench` and each corpus
# adapter's default root resolve.
_bench_into() {  # corpus, out_dir
  ( cd "${REPO_ROOT}/benchmarks" \
    && KEYHOG_BIN="${KEYHOG_BIN}" KEYHOG_NO_GPU=1 \
       python3 -m bench leaderboard --corpus "$1" --scanners keyhog --out "$2" )
}
# The regression gate: per-detector FP + overall-F1, candidate vs the pre-ship
# baseline. --no-beat-competitors because verify benches keyhog alone (a model
# is compared to its own prior self, not to competitors).
_gate_vs() {  # corpus, results_dir, baseline_dir
  ( cd "${REPO_ROOT}/benchmarks" \
    && python3 -m bench gate --corpus "$1" --results "$2" --baseline "$3" \
       --epsilon "${VERIFY_EPSILON}" --no-beat-competitors )
}
# Fail-closed revert: put the pre-ship model back and rebuild so the live binary
# never embeds a rejected candidate (Law 10 — never silently leave the worse
# model shipped).
_restore_and_rebuild() {
  if [[ -f "${WEIGHTS}.bak" ]]; then
    cp -f "${WEIGHTS}.bak" "${WEIGHTS}"
    echo "→ [verify] restored ${WEIGHTS} from .bak; rebuilding the known-good model" >&2
    ( cd "${REPO_ROOT}" && ${REBUILD_CMD} ) \
      || echo "WARNING: rebuild after restore FAILED — ${WEIGHTS} is reverted but the binary may be stale; rebuild manually" >&2
  else
    echo "WARNING: no ${WEIGHTS}.bak to restore — ${WEIGHTS} may still hold the rejected candidate; restore manually" >&2
  fi
}

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

# 2.5) [verify] Capture the PRE-SHIP baseline from the CURRENT binary, BEFORE the
#      train --write overwrites weights.bin — so the gate compares the candidate
#      against the exact model it replaces (honest per-detector FP / F1 deltas,
#      no stale committed baseline).
BASE_DIR=""
if [[ "${DO_VERIFY}" == "1" ]]; then
  BASE_DIR="$(mktemp -d -t keyhog-verify-base-XXXXXX)"
  echo "→ [verify] capturing pre-ship baseline (current model) on: ${VERIFY_CORPORA}"
  for c in ${VERIFY_CORPORA}; do
    _bench_into "${c}" "${BASE_DIR}" \
      || { echo "error: [verify] baseline bench failed for ${c}; aborting before any ship" >&2; exit 2; }
  done
fi

# 3) Retrain blended + validate on the leakage-free real held-out. The synthetic
#    F1 and real-recall gates live in train_classifier.py; without --write it
#    writes a scratch model and never touches the crate. With --write it ships
#    weights.bin (+ a .bak of the pre-ship model) iff the train-gates pass.
echo "→ retraining (synthetic + real, file-grouped held-out)"
python3 ml/train_classifier.py \
    --corpus "${SYN_CORPUS}" \
    --real-corpus "${REAL_OUT}" \
    --features "${FEATURES}" \
    "${WRITE_ARGS[@]}"

# 4) [verify] Rebuild with the shipped candidate, bench it, and gate each corpus
#    against the pre-ship baseline. Any per-detector FP spike or F1 regression →
#    fail-closed revert. This is the guard the train-gates structurally cannot be.
if [[ "${DO_WRITE}" == "1" && "${DO_VERIFY}" == "1" ]]; then
  echo "→ [verify] rebuilding keyhog with the shipped candidate model"
  if ! ( cd "${REPO_ROOT}" && ${REBUILD_CMD} ); then
    echo "error: [verify] rebuild failed; reverting" >&2
    _restore_and_rebuild
    exit 1
  fi
  CAND_DIR="$(mktemp -d -t keyhog-verify-cand-XXXXXX)"
  VERIFY_FAILED=0
  for c in ${VERIFY_CORPORA}; do
    if ! _bench_into "${c}" "${CAND_DIR}"; then
      echo "error: [verify] candidate bench failed for ${c}" >&2
      VERIFY_FAILED=1; break
    fi
    if ! _gate_vs "${c}" "${CAND_DIR}" "${BASE_DIR}"; then
      echo "✗ [verify] ${c}: per-detector FP / F1 regression gate FAILED" >&2
      VERIFY_FAILED=1
    fi
  done
  if [[ "${VERIFY_FAILED}" != "0" ]]; then
    echo "✗ [verify] regression detected — model REJECTED" >&2
    _restore_and_rebuild
    exit 1
  fi
  echo "✓ [verify] all corpora (${VERIFY_CORPORA}) passed the per-detector FP + F1 gate; candidate kept"
elif [[ "${DO_WRITE}" == "1" ]]; then
  cat >&2 <<'BANNER'
┌──────────────────────────────────────────────────────────────────────────┐
│ weights.bin SHIPPED, but the per-detector bench gate has NOT run.          │
│ Held-out F1/recall passing does NOT prove no per-detector FP regression —  │
│ the kubernetes-bootstrap-token +203-FP spike passed the held-out gates and │
│ only surfaced in the full CredData per-detector bench. Before trusting it: │
│   ml/retrain_loop.sh --write --verify     (re-ships + auto-verifies)       │
└──────────────────────────────────────────────────────────────────────────┘
BANNER
fi

if [[ "${DO_WRITE}" == "1" && "${DO_VERIFY}" == "1" ]]; then
  echo "✓ loop complete: model retrained, verified against the pre-ship baseline, and kept."
elif [[ "${DO_WRITE}" == "1" ]]; then
  echo "✓ loop complete: model shipped (train-gates passed). Run --write --verify to gate per-detector FP before trusting it."
else
  echo "✓ loop complete (measure-only). Re-run with --write [--verify] to ship + gate weights.bin."
fi
