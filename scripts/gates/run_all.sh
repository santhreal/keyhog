#!/usr/bin/env bash
# THE ONE prevention-gate entrypoint. Every audit keyhog has is invoked from
# here so a single `scripts/gates/run_all.sh` (and the one `audit-gates` CI job
# that runs it) is the whole story — not a scatter of gates a human has to
# remember to run. Each failure class that bit keyhog this round goes RED here,
# not into a sentence in CLAUDE.md someone can skip.
#
# Fast, always-run source/org gates (no corpus, no built binary, no network):
#   #1 no_silent_fallbacks   — new Law-10 swallow in a scan/CLI/verify crate (ratchet)
#   #1b law10_semantics      — Law-10 exemptions must prove conservation/loud surfacing
#   #1c no_stale_internal_refs — retired planning docs/registries cannot reappear
#   #1d site_truth           — website claims and detector catalog match source truth
#   #1e github_actions_pinned — repo CI cannot execute mutable third-party refs
#   #4 surface_coverage      — a subcommand with no real-process test
#   #5 complexity_budget     — engine grew a new lane/backend/file past budget
#   org_audit.py             — stale claims, generated LOC-cap bloat, evidence wiring
#   install_static_analysis  — install.sh/install.ps1 lint/static parser coverage
#   cli_claims_check.sh      — no hallucinated CLI flags in docs/site
#   entrypoints_check.sh     — pre-commit hook + composite Action stay wired
#   ci-operability           — workflow, metadata, fuzz/dogfood, and pin contracts
#
# Gates that need an asset (corpus / built binary / network / cargo-audit DB).
# These run when their asset is present and LOUD-SKIP (printed, never silent —
# Law 10) when not, so a developer box without the corpus still gets the source
# gates and CI (which HAS the assets) gets everything:
#   #2 backend parity        — a scan path silently diverges (pytest, needs corpus+bin)
#   #3 recall floor          — recall regressed below the pinned line (pytest)
#   bench gate               — keyhog must lead competitors + not regress (needs results/)
#   audit.sh                 — cargo audit (needs cargo-audit + advisory DB)
#   ml/parity_check.py       — Rust<->Python feature parity (skipped if ml/ absent)
#
# Usage:
#   scripts/gates/run_all.sh            # run every gate, loud-skip missing assets
#   STRICT_ASSETS=1 scripts/gates/run_all.sh   # treat a loud-skip as a FAILURE
#                                              # (CI uses this on the asset-bearing
#                                              # runner so a vanished corpus is red)
#   GATES_SOURCE_ONLY=1 scripts/gates/run_all.sh   # run ONLY the fast source/org
#                                              # gates; loud-skip every asset-bearing
#                                              # gate regardless of asset presence
#                                              # (the regression test + any box
#                                              # without the corpus/binaries use this)
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
rc=0
STRICT_ASSETS="${STRICT_ASSETS:-0}"
GATES_SOURCE_ONLY="${GATES_SOURCE_ONLY:-0}"

# Some source-surface tests intentionally run this entrypoint with a stripped
# environment. rustup/cargo need HOME to find the installed toolchain, so
# recover it from the account database instead of letting a missing HOME turn
# the CI-operability gate into an unrelated rustup failure.
if [ -z "${HOME:-}" ]; then
  HOME_FROM_PASSWD=""
  if command -v getent >/dev/null 2>&1; then
    HOME_FROM_PASSWD="$(getent passwd "$(id -u)" 2>/dev/null | cut -d: -f6 || true)"
  fi
  if [ -z "$HOME_FROM_PASSWD" ]; then
    HOME_FROM_PASSWD="$(cd ~ && pwd)"
  fi
  export HOME="$HOME_FROM_PASSWD"
fi
CARGO_BIN="${CARGO_BIN:-cargo}"
if [ "$CARGO_BIN" = "cargo" ] && [ -x "$HOME/.cargo/bin/cargo" ]; then
  CARGO_BIN="$HOME/.cargo/bin/cargo"
fi

# GATES_SOURCE_ONLY and STRICT_ASSETS are mutually exclusive: forcing every
# asset gate to skip while also failing on any skip would be a guaranteed red.
if [ "$GATES_SOURCE_ONLY" = "1" ] && [ "$STRICT_ASSETS" = "1" ]; then
  echo "FATAL: GATES_SOURCE_ONLY=1 and STRICT_ASSETS=1 are mutually exclusive." >&2
  exit 2
fi

# A gate whose asset is missing. Loud by contract (Law 10): we print exactly why
# and what to run to enable it. Under STRICT_ASSETS=1 a skip is a hard failure so
# the asset-bearing CI runner can never quietly drop a gate.
skip() {
  echo "  SKIP (loud): $1"
  if [ "$STRICT_ASSETS" = "1" ]; then
    echo "    STRICT_ASSETS=1 — treating this skip as a FAILURE." >&2
    rc=1
  fi
}

run() {
  # run "<label>" cmd args...  — print a banner, run, OR rc=1 on non-zero.
  local label="$1"; shift
  echo "== ${label} =="
  "$@" || rc=1
  echo
}

run "Gate #1 self-test: both idiom classes catch real fallbacks, ignore benign code" \
  python3 scripts/gates/no_silent_fallbacks.py --self-test
run "Gate #1: no silent fallbacks (scanner/sources/core/cli/verifier)" \
  python3 scripts/gates/no_silent_fallbacks.py
run "Gate #1b self-test: Law 10 semantic classifier catches unsafe waivers" \
  python3 scripts/gates/law10_semantics.py --self-test
run "Gate #1b: Law 10 annotations prove conservation or loud surfacing" \
  python3 scripts/gates/law10_semantics.py
run "Gate #1c self-test: stale internal planning refs are detected" \
  python3 scripts/gates/no_stale_internal_refs.py --self-test
run "Gate #1c: no stale internal planning refs outside absence contracts" \
  python3 scripts/gates/no_stale_internal_refs.py
run "Gate #1d self-test: stale website claims are detected" \
  python3 scripts/gates/site_truth.py --self-test
run "Gate #1d: website product claims and detector catalog match source truth" \
  python3 scripts/gates/site_truth.py
run "Gate #1e self-test: mutable GitHub Action refs are detected" \
  python3 scripts/gates/github_actions_pinned.py --self-test
run "Gate #1e: GitHub Actions are commit-pinned" \
  python3 scripts/gates/github_actions_pinned.py
run "Gate #4: surface coverage (every subcommand spawned)" \
  python3 scripts/gates/surface_coverage.py
run "Gate #5: complexity budget (engine lane/backend/file growth)" \
  python3 scripts/gates/complexity_budget.py
run "Vyre pin consistency: 5 crates lockstep, registry pins, no vendor build-path" \
  python3 scripts/gates/vyre_pin_consistency.py
run "Org audit: stale claims / LOC-cap bloat / evidence wiring" \
  python3 scripts/org_audit.py
run "Install static analysis: shell + PowerShell parser/linter coverage" \
  bash scripts/gates/install_static_analysis.sh
run "Docs CLI-claim gate: no hallucinated flags in docs/site" \
  bash tests/docs/cli_claims_check.sh
run "Integration entry-point gate: pre-commit hook + Action wired" \
  bash tests/integration/entrypoints_check.sh
run "CI operability: workflow and metadata contracts" \
  "$CARGO_BIN" test --manifest-path tools/ci-operability/Cargo.toml -- --nocapture

echo "== Gates #2 + #3: backend parity + recall floor (bench pytest) =="
if [ "$GATES_SOURCE_ONLY" = "1" ]; then
  skip "GATES_SOURCE_ONLY=1 — backend parity + recall floor pytest not run."
elif [ -d benchmarks/corpora/creddata/CredData/meta ]; then
  ( cd benchmarks && python3 -m pytest \
      bench/tests/test_backend_parity.py \
      bench/tests/test_creddata_recall_matrix.py::test_creddata_recall_does_not_regress_below_floor \
      -q --no-header -p no:cacheprovider ) || rc=1
else
  skip "CredData corpus not present — run \`make creddata\` to enable #2/#3."
fi
echo

echo "== Bench gate: keyhog must lead competitors + not regress past baseline =="
# The differential+regression gate consumes an already-produced leaderboard in
# benchmarks/results/ (run \`make leaderboard\` / the bench-nightly workflow
# first). We do NOT run a fresh leaderboard here — that needs every competitor
# binary on PATH and minutes of scan time; this entrypoint stays fast. If no
# results are present we loud-skip rather than run binaries that may be absent.
if [ "$GATES_SOURCE_ONLY" = "1" ]; then
  skip "GATES_SOURCE_ONLY=1 — differential bench gate not run."
elif [ -d benchmarks/results ] && \
   find benchmarks/results -name '*.json' -print -quit 2>/dev/null | grep -q .; then
  ( cd benchmarks && python3 -m bench gate \
      --corpus mirror --results results \
      --baseline baselines/mirror-keyhog-baseline.json --epsilon 0.005 ) || rc=1
else
  skip "no benchmarks/results/*.json — run \`make leaderboard\` (or the bench-nightly workflow) to enable the differential gate."
fi
echo

echo "== Security audit: cargo audit (advisory ignores from audit.toml) =="
if [ "$GATES_SOURCE_ONLY" = "1" ]; then
  skip "GATES_SOURCE_ONLY=1 — cargo audit not run."
elif command -v cargo-audit >/dev/null 2>&1 || cargo audit --version >/dev/null 2>&1; then
  bash scripts/audit.sh || rc=1
else
  skip "cargo-audit not installed — \`cargo install cargo-audit\` to enable the RUSTSEC gate."
fi
echo

echo "== ML feature parity: Rust dump_features vs ml/features.py =="
# parity_check.py compares the Rust serve-path feature extractor against the
# Python trainer port. It needs the Rust extractor: a prebuilt $KEYHOG_DUMP_FEATURES
# binary (what CI builds once and exports) — we do NOT trigger a cargo build from
# this fast entrypoint. Absent the script entirely, or the prebuilt binary, we
# loud-skip.
if [ "$GATES_SOURCE_ONLY" = "1" ]; then
  skip "GATES_SOURCE_ONLY=1 — ML feature-parity gate not run."
elif [ ! -f ml/parity_check.py ]; then
  skip "ml/parity_check.py absent — ML feature-parity gate not applicable in this tree."
elif [ -n "${KEYHOG_DUMP_FEATURES:-}" ] && [ -x "${KEYHOG_DUMP_FEATURES:-}" ]; then
  ( cd ml && python3 parity_check.py ) || rc=1
else
  skip "KEYHOG_DUMP_FEATURES (prebuilt dump_features binary) not set — build it (\`cargo build -p keyhog-scanner --example dump_features\`) and export its path to enable the ML parity gate without a cargo build from this entrypoint."
fi
echo

if [ $rc -eq 0 ]; then
  echo "ALL PREVENTION GATES GREEN."
else
  echo "PREVENTION GATES FAILED (rc=$rc)."
fi
exit $rc
