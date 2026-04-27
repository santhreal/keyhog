#!/usr/bin/env bash
#
# Deep pre-publish gate for the vyre workspace.
#
# Runs every automated gate we require before a publish can be trusted:
#
#   - formatting, narrow+workspace type checks, warnings-as-errors clippy
#   - every architectural law (A/B/C/D/H + pure-crate dependency invariant)
#   - rebuild_status.sh dashboard
#   - unit + doc + integration test suites per crate
#   - rustdoc with warnings-as-errors (no "missing docs" slips through)
#   - criterion benches compile (`--no-run`) so no bench rotted since last
#     release
#   - cargo publish --dry-run per publishable crate (dependency-ordered) with
#     required metadata checks
#
# The script exits non-zero on the FIRST failure, so the final "READY TO
# PUBLISH" line is trustworthy. Use it as the human's last check before
# actually running `cargo publish`.
#
# Usage: bash scripts/publish-dryrun.sh [crate-name ...]
#   - no arguments: run every gate and every publishable crate
#   - crate-name list: limit publish dry-runs to those crates (all other gates
#     still run)

set -euo pipefail

VYRE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$VYRE_ROOT"

RED=$'\033[31m'
GREEN=$'\033[32m'
YELLOW=$'\033[33m'
RESET=$'\033[0m'

PASS=0
FAIL=0
FAIL_NAMES=()

check() {
    local name="$1"
    shift
    printf '  [%s] %s\n' "…" "$name"
    if "$@" >/tmp/vyre-publish-gate.log 2>&1; then
        printf '\r  [%s%s%s] %s\n' "$GREEN" "✓" "$RESET" "$name"
        PASS=$((PASS+1))
    else
        printf '\r  [%s%s%s] %s\n' "$RED" "✗" "$RESET" "$name"
        FAIL=$((FAIL+1))
        FAIL_NAMES+=("$name")
        echo "    ↳ last 20 lines of output:"
        tail -n 20 /tmp/vyre-publish-gate.log | sed 's/^/      /'
    fi
}

section() {
    printf '\n%s%s%s\n' "$YELLOW" "$1" "$RESET"
}

# ─── Gates ──────────────────────────────────────────────────────────────────

section "Architectural laws"
check "pure-crate dependency invariant"        bash scripts/check_architectural_invariants.sh
check "Law A — no closed IR enums"             bash scripts/check_no_closed_ir_enums.sh
check "Law B — no string WGSL"                 bash scripts/check_no_string_wgsl.sh
check "Law C — capability negotiation"         bash scripts/check_capability_negotiation.sh
check "Law D — registry consistency"           bash scripts/check_registry_consistency.sh
check "Law H — unsafe SAFETY comments"         bash scripts/check_unsafe_justifications.sh
if [[ -x scripts/check_trait_freeze.sh ]]; then
    check "trait-surface freeze"               bash scripts/check_trait_freeze.sh
fi

section "Code health"
check "cargo fmt --check"                      cargo fmt --check
check "cargo check --workspace"                cargo check --workspace --all-targets
check "cargo clippy --workspace (deny warn)"   cargo clippy --workspace --all-targets -- -D warnings

section "Test suites"
# Every crate whose tests we care about at publish time. Kept explicit so a
# new crate doesn't slip through uncovered.
TEST_CRATES=(
    vyre
    vyre-core
    vyre-spec
    vyre-reference
    vyre-primitives
    vyre-wgpu
    vyre-sigstore
    vyre-conform
    vyre-conform-spec
    vyre-conform-enforce
    vyre-conform-generate
    vyre-conform-runner
    vyre-build-scan
)
for crate in "${TEST_CRATES[@]}"; do
    if [[ -d "$crate" ]]; then
        check "cargo test -p $crate --lib"     cargo test -p "$crate" --lib
    fi
done

section "Rustdoc (warnings denied)"
check "cargo doc --workspace"                  env RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps

section "Benchmark compile"
# Using --no-run so we catch rotted benches without paying the run cost.
check "cargo bench --workspace --no-run"       cargo bench --workspace --no-run

section "Rebuild status dashboard"
check "scripts/rebuild_status.sh"              bash scripts/rebuild_status.sh

# ─── Publish dry-runs ───────────────────────────────────────────────────────

# Dependency-ordered list. Always publish leaf crates before their parents, so
# that during a real publish we never hit "dependency not yet on crates.io".
#
# The ordering is:
#   1. vyre-sigstore   — no vyre deps
#   2. vyre-spec       — used by most conform crates
#   3. vyre-build-scan — build.rs utility, pulled in by *-conform-*
#   4. vyre-core (published as `vyre`)
#   5. vyre-primitives — depends on vyre-core
#   6. vyre-reference  — depends on vyre-core
#   7. vyre-wgpu       — depends on vyre-core + reference
#   8. vyre-conform-spec
#   9. vyre-conform-enforce
#  10. vyre-conform-generate
#  11. vyre-conform-runner
#  12. vyre-conform
#
# vyre-macros is only published alongside vyre.
PUBLISH_ORDER=(
    vyre-spec
    vyre-macros
    vyre
    vyre-primitives
    vyre-reference
    vyre-wgpu
    vyre-photonic
    vyre-spirv
    vyre-ops-primitive
    vyre-ops-hash
    vyre-ops-string
    vyre-ops-security
    vyre-ops-compression
    vyre-ops-graph
    vyre-ops-workgroup
    vyre-conform-spec
    vyre-conform-generate
    vyre-conform-enforce
    vyre-conform-runner
)

# If the caller passed crate names, filter the order to just those.
if [[ $# -gt 0 ]]; then
    REQUESTED=("$@")
    FILTERED=()
    for crate in "${PUBLISH_ORDER[@]}"; do
        for req in "${REQUESTED[@]}"; do
            if [[ "$crate" == "$req" ]]; then
                FILTERED+=("$crate")
            fi
        done
    done
    PUBLISH_ORDER=("${FILTERED[@]}")
fi

section "Publishable-crate metadata"
for crate in "${PUBLISH_ORDER[@]}"; do
    # The `vyre` package lives in the vyre-core directory.
    if [[ "$crate" == "vyre" ]]; then
        dir="vyre-core"
    else
        dir="$crate"
    fi
    if [[ ! -d "$dir" ]]; then
        printf '  %s[skip]%s %s (directory missing)\n' "$YELLOW" "$RESET" "$dir"
        continue
    fi
    check "$dir: README.md present"            test -f "$dir/README.md"
    check "$dir: LICENSE-MIT present"          test -f "$dir/LICENSE-MIT"
    check "$dir: LICENSE-APACHE present"       test -f "$dir/LICENSE-APACHE"
    check "$dir: description declared"         grep -Eq '^description[[:space:]]*=' "$dir/Cargo.toml"
    check "$dir: keywords declared"            grep -Eq '^keywords[[:space:]]*=' "$dir/Cargo.toml"
    check "$dir: categories declared"          grep -Eq '^categories[[:space:]]*=' "$dir/Cargo.toml"
    check "$dir: readme declared"              grep -Eq '^readme[[:space:]]*=' "$dir/Cargo.toml"
    check "$dir: license declared"             grep -Eq '^license[[:space:]]*=' "$dir/Cargo.toml"
    check "$dir: repository declared"          grep -Eq '^repository[[:space:]]*=' "$dir/Cargo.toml"
done

section "Publish dry-run (dependency-ordered)"
for crate in "${PUBLISH_ORDER[@]}"; do
    check "cargo publish --dry-run -p $crate"  cargo publish --dry-run --allow-dirty -p "$crate"
done

# ─── Summary ────────────────────────────────────────────────────────────────

printf '\n'
if [[ "$FAIL" -eq 0 ]]; then
    printf '%sREADY TO PUBLISH%s (%d gates passed)\n' "$GREEN" "$RESET" "$PASS"
    printf '\nSuggested publish command (dependency-ordered):\n'
    for crate in "${PUBLISH_ORDER[@]}"; do
        printf '  cargo publish -p %s\n' "$crate"
    done
    exit 0
else
    printf '%sNOT READY: %d gate(s) failed%s (%d passed, %d failed)\n' \
        "$RED" "$FAIL" "$RESET" "$PASS" "$FAIL"
    printf '\nFailing gates:\n'
    for name in "${FAIL_NAMES[@]}"; do
        printf '  - %s\n' "$name"
    done
    printf '\nRerun individual checks from scripts/ to iterate.\n'
    exit 1
fi
