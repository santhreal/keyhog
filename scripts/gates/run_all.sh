#!/usr/bin/env bash
# Local project-check entrypoint. Release automation does not call this script;
# the CI workflow owns the checks that must pass before a push can publish.
#
# Fast, always-run source/org gates (no corpus, no built binary, no network):
#   #1 no_silent_fallbacks: new Law-10 swallow in a scan/CLI/verify crate (ratchet)
#   #1b law10_semantics: Law-10 exemptions must prove conservation/loud surfacing
#   #1c no_stale_internal_refs, retired planning docs/registries cannot reappear
#   #1d no_deferral_markers, stale deferral markers cannot reappear
#   #1e docs_truth, canonical mdBook is complete and source-true
#   action_docs_contract: Action manifests and public reference tables stay exact
#   workflow_docs_boundaries: Action, direct CI, and mass scanning stay distinct
#   readme_matrix: generated accuracy/configuration/daemon/scaling panels stay provenance-bound
#   #1i doc_version_pins, documented action/install pins resolve to a real release
#   #1f github_actions_pinned, repo CI cannot execute mutable third-party refs
#   package_licenses: publishable crate roots carry canonical license bytes
#   #4 surface_coverage: a subcommand with no real-process test
#   #5 complexity_budget: engine growth, stale slack, or metric drift
#   org_audit.py: stale claims/owners, generated LOC-cap bloat, evidence wiring
#   install_static_analysis: install.sh/install.ps1 lint/static parser coverage
#   release_channel_coherence: an install/update path may not consume release
#     assets that no workflow produces, and a named workflow job must exist
#   cli_claims_check.sh: no hallucinated CLI flags in canonical docs
#   entrypoints_check.sh: pre-commit hook + composite Action stay wired
#   ci-operability: workflow, metadata, fuzz/dogfood, and pin contracts
#
# Gates that need an asset (corpus / built binary / network / cargo-audit DB).
# These run when their asset is present and LOUD-SKIP (printed, never silent 
# Law 10) when not, so a developer box without the corpus still gets the source
# gates and CI (which HAS the assets) gets everything:
#   #2 backend parity: a scan path silently diverges (pytest, needs corpus + full binary)
#       deterministic autoroute fixtures also need KEYHOG_AUTOROUTE_FIXTURE_BIN (ci-lean)
#   #3 recall floor: recall regressed below the pinned line (pytest)
#   docs_links: built mdBook has no broken local resources or fragments
#   bench gate, keyhog must lead competitors + not regress (needs results/)
#   audit.sh: cargo audit (needs cargo-audit + advisory DB)
#   ml/parity_check.py: Rust<->Python feature parity (skipped if ml/ absent)
#   coverage.sh: per-crate llvm-cov thresholds (needs cargo-llvm-cov)
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
export PYTHONDONTWRITEBYTECODE=1
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
rc=0
STRICT_ASSETS="${STRICT_ASSETS:-0}"
GATES_SOURCE_ONLY="${GATES_SOURCE_ONLY:-0}"

# Source/org gates must not leave Python bytecode cache clutter behind in the
# repo tree; org_audit.py enforces that invariant.
export PYTHONDONTWRITEBYTECODE=1

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
export CARGO_BIN

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
    echo "    STRICT_ASSETS=1, treating this skip as a FAILURE." >&2
    rc=1
  fi
}

run() {
  # run "<label>" cmd args... (print a banner, run, OR rc=1 on non-zero).
  local label="$1"; shift
  echo "== ${label} =="
  "$@" || rc=1
  echo
}

run "Gate #1 self-test: both idiom classes catch real fallbacks, ignore benign code" \
  python3 -B scripts/gates/no_silent_fallbacks.py --self-test
run "Gate #1: no silent fallbacks (scanner/sources/core/cli/verifier)" \
  python3 -B scripts/gates/no_silent_fallbacks.py
run "Gate #1b self-test: Law 10 semantic classifier catches unsafe waivers" \
  python3 -B scripts/gates/law10_semantics.py --self-test
run "Gate #1b: Law 10 annotations prove conservation or loud surfacing" \
  python3 -B scripts/gates/law10_semantics.py
run "Gate #1c self-test: stale internal planning refs are detected" \
  python3 -B scripts/gates/no_stale_internal_refs.py --self-test
run "Gate #1c: no stale internal planning refs outside absence contracts" \
  python3 -B scripts/gates/no_stale_internal_refs.py
run "Gate #1d self-test: stale deferral markers are detected" \
  python3 -B scripts/gates/no_deferral_markers.py --self-test
run "Gate #1d: no stale deferral markers in shipped surfaces" \
  python3 -B scripts/gates/no_deferral_markers.py
run "Gate #1e self-test: stale and duplicate documentation is detected" \
  python3 -B scripts/gates/docs_truth.py --self-test
run "Gate #1e: canonical mdBook documentation is complete and source-true" \
  python3 -B scripts/gates/docs_truth.py
run "GitHub Action documentation contract: manifests and references agree" \
  python3 -B scripts/gates/action_docs_contract.py
run "GitHub Action documentation tests: interface drift fails closed" \
  python3 -B -m unittest scripts.tests.test_action_docs_contract -v
run "Workflow documentation boundaries: Action, direct CI, and mass scanning stay distinct" \
  python3 -B scripts/gates/workflow_docs_boundaries.py
run "Workflow documentation boundary tests: routing and ownership fail closed" \
  python3 -B -m unittest scripts.tests.test_workflow_docs_boundaries -v
run "Pages metadata tests: canonical discovery output stays deterministic" \
  python3 -B -m unittest scripts.tests.test_docs_site -v
run "Repository star viewer: data and generated SVG agree" \
  python3 -B scripts/star_history.py --check
run "Repository star viewer tests: recording and rendering stay truthful" \
  python3 -B -m unittest scripts.tests.test_star_history -v
run "README benchmark matrix: snapshot, reports, and generated panels agree" \
  make -C benchmarks readme-matrix-check
run "Gate #1i self-test: dangling doc version pins are detected" \
  python3 -B scripts/gates/doc_version_pins.py --self-test
run "Gate #1i: documented action/install pins resolve to v0 or the current version" \
  python3 -B scripts/gates/doc_version_pins.py
run "Release documentation bump tests: measured benchmark provenance stays immutable" \
  python3 -B -m unittest scripts.tests.test_bump_doc_versions -v
run "Automatic release tests: green pushes bump, changelog, retry, and publish coherently" \
  python3 -B -m unittest scripts.tests.test_prepare_release scripts.tests.test_auto_release scripts.tests.test_release_workflows scripts.tests.test_publish_retry -v
run "Documentation truth tests: measured versions remain bound to evidence" \
  python3 -B -m unittest scripts.tests.test_docs_truth -v
run "Crate changelog gate: every publishable crate has release notes" \
  python3 -B scripts/gates/crate_changelogs.py --allow-released \
    crates/cli/CHANGELOG.md crates/core/CHANGELOG.md crates/scanner/CHANGELOG.md \
    crates/sources/CHANGELOG.md crates/verifier/CHANGELOG.md
run "Crate changelog tests: missing and empty release sections fail closed" \
  python3 -B -m unittest scripts.tests.test_crate_changelogs -v
run "Package license gate: publishable crate roots use canonical bytes" \
  python3 -B scripts/gates/package_licenses.py
run "Gate #1f self-test: mutable GitHub Action refs are detected" \
  python3 -B scripts/gates/github_actions_pinned.py --self-test
run "Gate #1f: GitHub Actions are commit-pinned" \
  python3 -B scripts/gates/github_actions_pinned.py
run "Gate #1g self-test: CI-orphan scanner regression detection" \
  python3 -B scripts/gates/recall_locks_wired.py --self-test
run "Gate #1g: every scanner regression_*.rs is CI-wired (all_tests or --test)" \
  python3 -B scripts/gates/recall_locks_wired.py
run "Gate #1h self-test: CI-orphan test detection (verifier + core)" \
  python3 -B scripts/gates/tests_wired.py --self-test
run "Gate #1h: every enforced-crate tests/*.rs is CI-wired (all_tests or --test)" \
  python3 -B scripts/gates/tests_wired.py
run "Gate #4: surface coverage (every subcommand spawned)" \
  python3 -B scripts/gates/surface_coverage.py
run "Gate #5: exact complexity ratchet (growth, slack, and metric drift)" \
  python3 -B scripts/gates/complexity_budget.py
run "VYRE pin consistency: 6 crates at one immutable Git revision, no vendor build-path" \
  python3 -B scripts/gates/vyre_pin_consistency.py
run "GPU wiring self-test: unfeatured, absorbed, orphaned, and unarmed GPU lanes are detected" \
  python3 -B scripts/gates/gpu_wired.py --self-test
run "GPU wiring: GPU targets are feature-built, unabsorbed, wired, and the release lane is armed" \
  python3 -B scripts/gates/gpu_wired.py
run "GPU wiring unit tests: static fixture workflows and folded scalar parsing" \
  python3 -B -m unittest scripts.tests.test_gpu_wired -v
run "Release channel self-test: frozen channels and phantom workflow jobs are detected" \
  python3 -B scripts/gates/release_channel_coherence.py --self-test
run "Release channel coherence: no install path consumes assets no workflow produces" \
  python3 -B scripts/gates/release_channel_coherence.py
run "Continue-on-error self-test: un-prefixed absorbed test/lint steps are detected" \
  python3 -B scripts/gates/no_continue_on_error.py --self-test
run "Continue-on-error: workflow error absorption adheres to Row 5 informational policy" \
  python3 -B scripts/gates/no_continue_on_error.py
run "Continue-on-error unit tests: static workflow error absorption analysis" \
  python3 -B -m unittest scripts.tests.test_no_continue_on_error -v
run "Vacuous test self-test: capability-conditional tests without safe policies are detected" \
  python3 -B scripts/gates/vacuous_tests.py --self-test
run "Vacuous tests: capability-conditional tests safely arm policies or register outcomes" \
  python3 -B scripts/gates/vacuous_tests.py
run "Vacuous tests unit tests: static early-return analysis across test targets" \
  python3 -B -m unittest scripts.tests.test_vacuous_tests -v
run "Regression contracts self-test: class-closing WHY comments and variant derivation" \
  python3 -B scripts/gates/regression_contracts.py --self-test
run "Regression contracts: class-closing WHY comments and runtime variant derivation" \
  python3 -B scripts/gates/regression_contracts.py
run "Regression contracts unit tests: static analysis of class-closing regression tests" \
  python3 -B -m unittest scripts.tests.test_regression_contracts -v
run "Profile divergence self-test: semantic vs cosmetic profile key taxonomy" \
  python3 -B scripts/gates/profile_divergence.py --self-test
run "Profile divergence: workspace profile table keys are classified and release unwinds" \
  python3 -B scripts/gates/profile_divergence.py
run "Profile divergence unit tests: static analysis of profile tables" \
  python3 -B -m unittest scripts.tests.test_profile_divergence -v
run "Unsafe guards self-test: safety precondition and debug_assert hazard detection" \
  python3 -B scripts/gates/unsafe_guards.py --self-test
run "Unsafe guards: workspace unsafe blocks carry written safety preconditions and release asserts" \
  python3 -B scripts/gates/unsafe_guards.py
run "Unsafe guards unit tests: static analysis of unsafe block invariants" \
  python3 -B -m unittest scripts.tests.test_unsafe_guards -v
run "Artifact size ceiling self-test: release profile strip and platform ceilings" \
  python3 -B scripts/gates/artifact_size_ceiling.py --self-test
run "Artifact size ceiling: release profiles strip symbols and binaries meet ceilings" \
  python3 -B scripts/gates/artifact_size_ceiling.py
run "Artifact size ceiling unit tests: platform ceiling thresholds" \
  python3 -B -m unittest scripts.tests.test_artifact_size_ceiling -v
run "Unified counter ownership self-test: single counter owner and static mapping" \
  python3 -B scripts/gates/unified_counter_ownership.py --self-test
run "Unified counter ownership: profile metrics ownership and zero stray counters" \
  python3 -B scripts/gates/unified_counter_ownership.py
run "Unified counter ownership unit tests: static analysis of process-global counter ownership" \
  python3 -B -m unittest scripts.tests.test_unified_counter_ownership -v
run "Unified host parallelism self-test: single host width owner and zero stray queries" \
  python3 -B scripts/gates/unified_host_parallelism.py --self-test
run "Unified host parallelism: canonical keyhog_profile host width ownership" \
  python3 -B scripts/gates/unified_host_parallelism.py
run "Unified window overlap self-test: single canonical window overlap owner and zero redeclarations" \
  python3 -B scripts/gates/unified_window_overlap.py --self-test
run "Unified window overlap: canonical keyhog_core window overlap ownership" \
  python3 -B scripts/gates/unified_window_overlap.py
run "Unified byte size parser self-test: single canonical byte size parser and zero private implementations" \
  python3 -B scripts/gates/unified_byte_size_parser.py --self-test
run "Unified byte size parser: canonical value_parsers::parse_byte_size ownership" \
  python3 -B scripts/gates/unified_byte_size_parser.py
run "Unified operational constants self-test: configuration schema reflection and range validation" \
  python3 -B scripts/gates/unified_operational_constants.py --self-test
run "Unified operational constants: Tier-A operational performance knobs governance" \
  python3 -B scripts/gates/unified_operational_constants.py
run "Timing log profile identity self-test: diagnostic log lines without profile identity are detected" \
  python3 -B scripts/gates/timing_log_profile_identity.py --self-test
run "Timing log profile identity: all diagnostic timing figures derive from registered profile metrics" \
  python3 -B scripts/gates/timing_log_profile_identity.py
run "Timing log profile identity unit tests: static analysis of diagnostic timing logging" \
  python3 -B -m unittest scripts.tests.test_timing_log_profile_identity -v
run "Mutation gate self-test: AST mutation generator catches surviving mutants" \
  python3 -B scripts/gates/mutation_gate.py --self-test
run "Mutation gate unit tests: operator inversion and comment preservation" \
  python3 -B -m unittest scripts.tests.test_mutation_gate -v
run "Organization unit tests: exact complexity ratchet and owner/reference checks" \
  python3 -B -m unittest scripts.tests.test_complexity_budget scripts.tests.test_org_audit -v
run "tests_wired unit tests: CI-orphan model (path/mod/--test/all-targets/pkg)" \
  python3 -B -m unittest scripts.tests.test_tests_wired -v
run "Automatic release workflow tests: successful main CI is the only publisher" \
  python3 -B -m unittest scripts.tests.test_release_workflows -v
run "Org audit: stale claims / LOC-cap bloat / evidence wiring" \
  python3 -B scripts/org_audit.py
run "Install static analysis: shell + PowerShell parser/linter coverage" \
  bash scripts/gates/install_static_analysis.sh
run "Docs CLI-claim gate: no hallucinated flags in docs/site" \
  bash tests/docs/cli_claims_check.sh
run "Integration entry-point gate: pre-commit hook + Action wired" \
  bash tests/integration/entrypoints_check.sh
run "CI operability: workflow and metadata contracts" \
  "$CARGO_BIN" test --manifest-path tools/ci-operability/Cargo.toml -- --nocapture

echo "== Built documentation links: local resources and fragments resolve =="
if [ -d docs/book ] && [ -f docs/book/index.html ]; then
  python3 -B scripts/gates/docs_links.py docs/book --site-prefix /keyhog/ || rc=1
else
  skip "docs/book is absent (run \`cd docs && mdbook build\` to enable the built-link gate)."
fi
echo

echo "== Gates #2 + #3: backend parity + recall floor (bench pytest) =="
if [ "$GATES_SOURCE_ONLY" = "1" ]; then
  skip "GATES_SOURCE_ONLY=1 (backend parity + recall floor pytest not run)."
elif [ -d benchmarks/corpora/creddata/CredData/meta ]; then
  if [ -z "${KEYHOG_AUTOROUTE_FIXTURE_BIN:-}" ]; then
    skip "KEYHOG_AUTOROUTE_FIXTURE_BIN is unset (build a current ci-lean binary to enable deterministic autoroute timing-fixture tests)."
  fi
  ( cd benchmarks && python3 -B -m pytest -p no:cacheprovider \
      bench/tests/test_backend_parity.py \
      bench/tests/test_creddata_recall_matrix.py::test_creddata_recall_does_not_regress_below_floor \
      -q --no-header ) || rc=1
else
  skip "CredData corpus not present (run \`make creddata\` to enable #2/#3)."
fi
echo

echo "== Bench gate: keyhog must lead competitors + not regress past baseline =="
# The differential+regression gate consumes an already-produced leaderboard in
# benchmarks/results/ (run \`make leaderboard\` / the bench-nightly workflow
# first). We do NOT run a fresh leaderboard here, that needs every competitor
# binary on PATH and minutes of scan time; this entrypoint stays fast. If no
# results are present we loud-skip rather than run binaries that may be absent.
if [ "$GATES_SOURCE_ONLY" = "1" ]; then
  skip "GATES_SOURCE_ONLY=1 (differential bench gate not run)."
elif [ -d benchmarks/results ] && \
   find benchmarks/results -name '*.json' -print -quit 2>/dev/null | grep -q .; then
  ( cd benchmarks && python3 -B -m bench gate \
      --corpus mirror --results results \
      --baseline baselines/mirror-keyhog-baseline.json --epsilon 0.005 ) || rc=1
else
  skip "no benchmarks/results/*.json (run \`make leaderboard\` (or the bench-nightly workflow) to enable the differential gate)."
fi
echo

echo "== Coverage gate: per-crate llvm-cov thresholds =="
if [ "$GATES_SOURCE_ONLY" = "1" ]; then
  skip "GATES_SOURCE_ONLY=1 (coverage gate not run)."
elif "$CARGO_BIN" llvm-cov --version >/dev/null 2>&1; then
  bash scripts/gates/coverage.sh --enforce || rc=1
else
  skip "cargo-llvm-cov not installed: \`cargo install cargo-llvm-cov\` to enable the coverage gate."
fi
echo

echo "== Security audit: cargo audit (advisory ignores from audit.toml) =="
if [ "$GATES_SOURCE_ONLY" = "1" ]; then
  skip "GATES_SOURCE_ONLY=1 (cargo audit not run)."
elif command -v cargo-audit >/dev/null 2>&1 || cargo audit --version >/dev/null 2>&1; then
  bash scripts/audit.sh || rc=1
else
  skip "cargo-audit not installed: \`cargo install cargo-audit\` to enable the RUSTSEC gate."
fi
echo

echo "== ML feature parity: Rust dump_features vs ml/feature_parity.py =="
# parity_check.py compares the Rust serve-path feature extractor against the
# Python parity/debug port. It needs the Rust extractor: a prebuilt $KEYHOG_DUMP_FEATURES
# binary (what CI builds once and exports), we do NOT trigger a cargo build from
# this fast entrypoint. Absent the script entirely, or the prebuilt binary, we
# loud-skip.
if [ "$GATES_SOURCE_ONLY" = "1" ]; then
  skip "GATES_SOURCE_ONLY=1: ML feature-parity gate not run."
elif [ ! -f ml/parity_check.py ]; then
  skip "ml/parity_check.py absent. ML feature-parity gate not applicable in this tree."
elif [ -n "${KEYHOG_DUMP_FEATURES:-}" ] && [ -x "${KEYHOG_DUMP_FEATURES:-}" ]; then
  ( cd ml && python3 -B parity_check.py ) || rc=1
else
  skip "KEYHOG_DUMP_FEATURES (prebuilt dump_features binary) not set, build it (\`cargo build -p keyhog-scanner --example dump_features\`) and export its path to enable the ML parity gate without a cargo build from this entrypoint."
fi
echo

if [ $rc -eq 0 ]; then
  echo "ALL PREVENTION GATES GREEN."
else
  echo "PREVENTION GATES FAILED (rc=$rc)."
fi
exit $rc
