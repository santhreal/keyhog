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
#   ml/retrain_loop.sh --write --verify     # ship, then REBUILD + per-detector FP gate
#                                           #   + full contract-recall gate;
#                                           #   auto-revert weights.bin on any regression
#   KEYHOG_BIN=/path/to/keyhog ml/retrain_loop.sh   # explicit external harvester
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
#
# Contract-recall gate (--verify, second guard): the bench above is BLIND to the
# known-positive contract fixtures, so a model that suppresses generic/entropy
# contract positives passes the bench yet breaks the contract CI gate (how
# moe-v1-1cbb8088 shipped with CredData F1 +0.088 but MISSED 13 contract positives
# on 2026-07-07). --verify now also runs contracts_runner against the candidate and
# fail-closed reverts on any contract failure (VERIFY_CONTRACTS=0 disables, iteration only).
set -euo pipefail

ML_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${ML_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

CORPORA="${CORPORA:-creddata}"
REAL_OUT="${REAL_OUT:-ml/data/real_corpus.jsonl}"
SYN_CORPUS="${SYN_CORPUS:-ml/data/corpus.jsonl}"
FEATURES="${FEATURES:-43}"
WEIGHTS="${WEIGHTS:-crates/scanner/src/weights.bin}"
# The model card is written+backed-up alongside weights.bin by train_classifier's
# write_model_card. build.rs enforces weights.bin <-> model_card consistency
# (model_version + weights_fnv1a64), so a fail-closed revert MUST restore BOTH or
# the post-revert rebuild fails the consistency check and leaves the tree in a
# weights=baseline / card=candidate mismatch.
MODEL_CARD="${MODEL_CARD:-crates/scanner/src/model_card.json}"
# Corpora the bench-verify gate runs on. mirror = the precision guardian, creddata
# = the real-distribution recall corpus where the prior regression surfaced.
VERIFY_CORPORA="${VERIFY_CORPORA:-mirror creddata}"
VERIFY_EPSILON="${VERIFY_EPSILON:-0.005}"
# Rebuild command for the bench-verify (weights.bin is include_bytes!-embedded, so
# a candidate model is only observable after a rebuild). Override for a different
# feature set / profile.
REBUILD_CMD="${REBUILD_CMD:-cargo build --release -p keyhog --bin keyhog --features simd}"

# Resolve the cargo target-dir the same way the bench adapter does (env →
# ~/.cargo/config.toml `target-dir` → <repo>/target) so VERIFY_BIN points at the
# binary REBUILD_CMD actually produces — not a stale sibling profile. This was a
# real footgun: the harvest auto-resolver preferred release-fast/keyhog while
# REBUILD_CMD builds release/keyhog, so verify would have benched an un-rebuilt
# stale binary and gated it against itself (verifying nothing).
_resolve_target_dir() {
  if [[ -n "${CARGO_TARGET_DIR:-}" ]]; then echo "${CARGO_TARGET_DIR}"; return; fi
  local cfg d
  for cfg in "${HOME}/.cargo/config.toml" "${HOME}/.cargo/config"; do
    if [[ -f "${cfg}" ]]; then
      d="$(grep -oP '^\s*target-dir\s*=\s*"\K[^"]+' "${cfg}" 2>/dev/null | head -1 || true)"
      [[ -n "${d}" ]] && { echo "${d}"; return; }
    fi
  done
  echo "${REPO_ROOT}/target"
}
TARGET_DIR="$(_resolve_target_dir)"
# The binary REBUILD_CMD writes (default `--release`). If you override REBUILD_CMD
# to a different profile, set VERIFY_BIN to match its output path.
VERIFY_BIN="${VERIFY_BIN:-${TARGET_DIR}/release/keyhog}"

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
# A leaderboard run for one corpus into a results dir, scored on an EXPLICIT
# binary (`--no-gpu` = the deterministic filesystem path the gate baselines were
# captured on). The binary is passed in, never the ambient KEYHOG_BIN, so
# the candidate bench provably scores the freshly-rebuilt VERIFY_BIN. Run from
# benchmarks/ so `bench` and each corpus adapter's default root resolve.
_bench_into() {  # bin, corpus, out_dir
  ( cd "${REPO_ROOT}/benchmarks" \
    && KEYHOG_BIN="$1" \
       python3 -m bench leaderboard --corpus "$2" --scanners keyhog --out "$3" )
}
_rebuild() {  # rebuild VERIFY_BIN from the current weights.bin
  ( cd "${REPO_ROOT}" && ${REBUILD_CMD} )
}
# The regression gate: per-detector FP + overall-F1, candidate vs the pre-ship
# baseline. --no-beat-competitors because verify benches keyhog alone (a model
# is compared to its own prior self, not to competitors).
_gate_vs() {  # corpus, results_dir, baseline_dir
  ( cd "${REPO_ROOT}/benchmarks" \
    && python3 -m bench gate --corpus "$1" --results "$2" --baseline "$3" \
       --epsilon "${VERIFY_EPSILON}" --no-beat-competitors )
}
# Contract-recall gate (--verify): the per-detector FP/F1 bench above is BLIND to
# the known-positive contract fixtures. A model that suppresses generic/entropy
# contract positives (`password=<real>`, `{"secret":"<real>"}`) sails through the
# bench yet breaks the hard contract CI gate — exactly how moe-v1-1cbb8088 shipped
# past --verify on 2026-07-07 (CredData F1 +0.088, mirror recall flat) while MISSING
# 13 contract positives (generic-password + 8 JSON-wrapped evasions). Running
# contracts_runner against the just-shipped candidate closes that hole so --verify
# is honest. Absolute (candidate must pass ALL contracts): if the tree's contracts
# are already red from concurrent work, fix the tree before shipping a model. Set
# VERIFY_CONTRACTS=0 only for throwaway iteration, never for a real ship.
VERIFY_CONTRACTS="${VERIFY_CONTRACTS:-1}"
_contracts_gate() {  # run the full contract suite against the current candidate weights.bin
  ( cd "${REPO_ROOT}" \
    && CARGO_TARGET_DIR="${TARGET_DIR}" cargo test -p keyhog-scanner --test contracts_runner )
}
# Fail-closed revert: put the pre-ship model back and rebuild so the live binary
# never embeds a rejected candidate (Law 10 — never silently leave the worse
# model shipped).
_restore_and_rebuild() {
  if [[ ! -f "${WEIGHTS}.bak" ]]; then
    echo "error: no ${WEIGHTS}.bak to restore; refusing to leave rejected model state ambiguous" >&2
    return 1
  fi
  cp -f "${WEIGHTS}.bak" "${WEIGHTS}"
  # Restore the model card too, so build.rs's weights<->card consistency check
  # passes on the post-revert rebuild (Law-10: never leave a mismatched pair).
  if [[ -f "${MODEL_CARD}.bak" ]]; then
    cp -f "${MODEL_CARD}.bak" "${MODEL_CARD}"
    echo "→ [verify] restored ${MODEL_CARD} from .bak (weights<->card kept consistent)" >&2
  fi
  echo "→ [verify] restored ${WEIGHTS} from .bak; rebuilding the known-good model" >&2
  if ! _rebuild; then
    echo "error: rebuild after restore failed; live binary may still embed the rejected candidate" >&2
    return 1
  fi
}

# 1) Resolve a keyhog binary to harvest with. In --verify mode the harvest + the
#    baseline must reflect the EXACT current weights.bin, so we rebuild VERIFY_BIN
#    first and harvest with it (no stale-sibling ambiguity). Outside --verify,
#    an explicit KEYHOG_BIN is honored; otherwise the loop rebuilds VERIFY_BIN
#    from the current tree before harvest. It never auto-picks a stale sibling
#    binary from target/ or PATH.
USER_KEYHOG_BIN="${KEYHOG_BIN:-}"
if [[ "${DO_VERIFY}" == "1" ]]; then
  echo "→ [verify] rebuilding the current model so the baseline binary matches weights.bin"
  _rebuild || { echo "error: [verify] pre-ship rebuild failed; aborting before any change" >&2; exit 2; }
  KEYHOG_BIN="${VERIFY_BIN}"
elif [[ -z "${USER_KEYHOG_BIN}" ]]; then
  echo "→ rebuilding current keyhog for harvest: ${REBUILD_CMD}"
  if ! _rebuild; then
    echo "error: harvest rebuild failed; set KEYHOG_BIN=/path/to/a/current/keyhog" \
      "only if you intentionally want an external harvester" >&2
    exit 2
  fi
  KEYHOG_BIN="${VERIFY_BIN}"
else
  KEYHOG_BIN="${USER_KEYHOG_BIN}"
fi
if [[ ! -x "${KEYHOG_BIN}" ]]; then
  echo "error: keyhog binary is not executable: ${KEYHOG_BIN}" >&2
  exit 2
fi
if ! KEYHOG_VERSION="$("${KEYHOG_BIN}" --version 2>&1)"; then
  echo "error: keyhog binary failed --version: ${KEYHOG_BIN}" >&2
  printf '%s\n' "${KEYHOG_VERSION}" >&2
  exit 2
fi
echo "→ keyhog: ${KEYHOG_BIN} (${KEYHOG_VERSION})"

# 2) Harvest the real distribution (labels via the bench's ground-truth overlap).
echo "→ harvesting real corpus: ${CORPORA}"
python3 ml/harvest_corpus.py --corpora ${CORPORA} --keyhog-bin "${KEYHOG_BIN}" --out "${REAL_OUT}"

# 2b) Blend the detector contract fixtures in as labeled training data
#     (positive/evasion=1, negative=0). CredData alone never taught the model
#     these context-anchored medium-entropy shapes, so a precision retrain drops
#     them — moe-v1-1cbb8088 shipped past the bench gate but MISSED 13 contract
#     positives. Blending them (+ their placeholder negatives, which reinforce
#     precision) is what lets a precision retrain also clear the contract gate.
#     Contract records force into the train split (train_classifier._group_split)
#     so they never dilute the honest CredData held-out. Set CONTRACT_CORPUS to a
#     pre-generated jsonl: `python3 ml/gen_contract_corpus.py ml/data/contract_corpus.jsonl`.
if [[ -n "${CONTRACT_CORPUS:-}" ]]; then
  if [[ ! -f "${CONTRACT_CORPUS}" ]]; then
    echo "error: CONTRACT_CORPUS set but not found: ${CONTRACT_CORPUS}" >&2; exit 2
  fi
  n_before="$(wc -l < "${REAL_OUT}")"
  cat "${CONTRACT_CORPUS}" >> "${REAL_OUT}"
  echo "→ blended contract fixtures into real corpus: ${n_before} -> $(wc -l < "${REAL_OUT}") records"
fi

# 2.5) [verify] Capture the PRE-SHIP baseline from VERIFY_BIN (just rebuilt from
#      the current weights.bin), BEFORE train --write overwrites it — so the gate
#      compares the candidate against the exact model it replaces (honest
#      per-detector FP / F1 deltas, no stale committed baseline).
BASE_DIR=""
if [[ "${DO_VERIFY}" == "1" ]]; then
  BASE_DIR="$(mktemp -d -t keyhog-verify-base-XXXXXX)"
  echo "→ [verify] capturing pre-ship baseline (current model) on: ${VERIFY_CORPORA}"
  for c in ${VERIFY_CORPORA}; do
    _bench_into "${VERIFY_BIN}" "${c}" "${BASE_DIR}" \
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

# 4) [verify] Rebuild with the shipped candidate, bench VERIFY_BIN, and gate each
#    corpus against the pre-ship baseline. Any per-detector FP spike or F1
#    regression → fail-closed revert. This is the guard train-gates cannot be.
if [[ "${DO_WRITE}" == "1" && "${DO_VERIFY}" == "1" ]]; then
  echo "→ [verify] rebuilding keyhog with the shipped candidate model"
  if ! _rebuild; then
    echo "error: [verify] candidate rebuild failed; reverting" >&2
    _restore_and_rebuild || exit 2
    exit 1
  fi
  CAND_DIR="$(mktemp -d -t keyhog-verify-cand-XXXXXX)"
  VERIFY_FAILED=0
  for c in ${VERIFY_CORPORA}; do
    if ! _bench_into "${VERIFY_BIN}" "${c}" "${CAND_DIR}"; then
      echo "error: [verify] candidate bench failed for ${c}" >&2
      VERIFY_FAILED=1; break
    fi
    if ! _gate_vs "${c}" "${CAND_DIR}" "${BASE_DIR}"; then
      echo "✗ [verify] ${c}: per-detector FP / F1 regression gate FAILED" >&2
      VERIFY_FAILED=1
    fi
  done
  # Contract-recall gate — the bench above cannot see the known-positive
  # fixtures; run them against the candidate so a generic/entropy recall
  # regression can't slip through (the moe-v1-1cbb8088 failure mode).
  if [[ "${VERIFY_FAILED}" == "0" && "${VERIFY_CONTRACTS}" == "1" ]]; then
    echo "→ [verify] contract-recall gate: full known-positive fixture suite (bench-blind)"
    if ! _contracts_gate; then
      echo "✗ [verify] contract-recall gate FAILED — candidate suppresses known-positive contract fixtures" >&2
      VERIFY_FAILED=1
    fi
  fi
  if [[ "${VERIFY_FAILED}" != "0" ]]; then
    echo "✗ [verify] regression detected — model REJECTED" >&2
    _restore_and_rebuild || exit 2
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
