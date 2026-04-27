#!/usr/bin/env bash
# Legendary sign-off composite gate (§39 of LEGENDARY.md).
#
# Runs every architectural invariant the vyre shard plans defined. Used
# as the pre-publish quality floor for every release in the v0.5.x → v1.0
# arc. A failing run means the workspace is NOT in a legendary-ready
# state. A passing run is necessary but not sufficient for v1.0.0 — the
# §39 acceptance checklist (external extension demo, three-substrate
# parity, benchmark reproducibility, publish dry-run green) is the
# final gate.
#
# Usage:
#   scripts/check_legendary_signoff.sh            # run all gates (CI)
#   scripts/check_legendary_signoff.sh --list     # list gates, don't run

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# Gate inventory. Each is a script that exits 0 on pass, non-zero on fail.
#
# Order matters only for readability; every gate runs unconditionally so a
# failing early gate does not mask a failing later gate. Ordering clusters
# gates by concern (surface, trait-freeze, wire-format, runtime, consumer).
GATES=(
    # Surface invariants: what shape of code is legal in 0.6.
    "scripts/check_no_closed_ir_enums.sh"
    "scripts/check_no_shader_assets.sh"
    "scripts/check_no_string_wgsl.sh"
    "scripts/check_no_parse_str.sh"
    "scripts/check_architectural_invariants.sh"
    "scripts/check_trait_freeze.sh"
    # Registry + dialect coverage: every op is registered once, every backend
    # declares a lowering, every cap query answers honestly.
    "scripts/check_registry_consistency.sh"
    "scripts/check_capability_negotiation.sh"
    "scripts/check_dialect_coverage.sh"
    # Hygiene: no raw unwrap, no uncommented unsafe, no hot-path inventory
    # iteration, no parallel OpSpec catalog, error codes cataloged, expects
    # carry a Fix: prefix.
    "scripts/check_unsafe_justifications.sh"
    "scripts/check_expect_has_fix.sh"
    "scripts/check_no_raw_unwrap.sh"
    "scripts/check_no_hot_path_inventory.sh"
    "scripts/check_no_opspec_tokens.sh"
    "scripts/check_error_codes_cataloged.sh"
    "scripts/check_consistency_contracts.sh"
    "scripts/check_base_monument.sh"
    # Workspace + wire format + warnings: shape invariants that a publish dry-run
    # would otherwise catch late.
    "scripts/check_workspace_filesystem.sh"
    "scripts/check_invariant_paths_exist.sh"
    "scripts/check_warning_budget.sh"
    "scripts/check_wire_version_migration.sh"
    "scripts/check_repo_hygiene.sh"
    # Layering + consumer dry-check: the 0.6 R5-strict layering rule and the
    # cargo-check smoke against known downstream consumers (surgec / pyrograph
    # / warpscan) catches API-shape breakage before publish.
    "scripts/check_layering.sh"
    "scripts/check_consumers.sh"
    # Public-API + readme truth: doc claims must match the code; API snapshot
    # must match the trait-freeze contract.
    "scripts/check_public_api_snapshot.sh"
    "scripts/check_readme_claims.sh"
    # Tests: gap tests designed to fail; this gate confirms they still fail
    # (failing gap tests are findings, not bugs — see LAW 5).
    "scripts/check_tests_can_fail.sh"
)

if [[ "${1:-}" == "--list" ]]; then
    echo "Legendary sign-off gates:"
    for gate in "${GATES[@]}"; do
        if [[ -x "$gate" ]]; then
            echo "  [exe] $gate"
        elif [[ -f "$gate" ]]; then
            echo "  [file] $gate (not executable)"
        else
            echo "  [missing] $gate"
        fi
    done
    exit 0
fi

failed=()
missing=()
passed=()

for gate in "${GATES[@]}"; do
    if [[ ! -f "$gate" ]]; then
        missing+=("$gate")
        continue
    fi
    if [[ ! -x "$gate" ]]; then
        chmod +x "$gate" || true
    fi
    echo "========================================"
    echo "Running: $gate"
    echo "========================================"
    if "$gate"; then
        passed+=("$gate")
    else
        failed+=("$gate")
    fi
done

echo ""
echo "========================================"
echo "Legendary sign-off summary"
echo "========================================"
echo "Passed: ${#passed[@]} / ${#GATES[@]}"
echo "Failed: ${#failed[@]} / ${#GATES[@]}"
echo "Missing: ${#missing[@]} / ${#GATES[@]}"

if [[ ${#failed[@]} -gt 0 ]]; then
    echo ""
    echo "Failed gates:"
    for gate in "${failed[@]}"; do
        echo "  ✗ $gate"
    done
fi
if [[ ${#missing[@]} -gt 0 ]]; then
    echo ""
    echo "Missing gates (not yet authored):"
    for gate in "${missing[@]}"; do
        echo "  ? $gate"
    done
fi

if [[ ${#failed[@]} -gt 0 || ${#missing[@]} -gt 0 ]]; then
    echo ""
    echo "Legendary sign-off: NOT READY."
    echo "Fix the failing/missing gates before tagging v1.0.0."
    exit 1
fi

echo ""
echo "Legendary sign-off: all ${#GATES[@]} gates green."
echo ""
echo "Final acceptance checklist (§39 of LEGENDARY.md) — verify manually:"
echo "  [ ] external_ir_extension example <200 LOC, CI green, zero core edits"
echo "  [ ] wgpu + spirv byte-identical across full primitive corpus"
echo "  [ ] zero reference code in vyre-core"
echo "  [ ] every op has a signed cert byte-identical across machines"
echo "  [ ] real reproducible bench numbers in benches/RESULTS.md"
echo "  [ ] vyre-core/src/ has <400 .rs files"
echo "  [ ] every expect starts with 'Fix:'"
echo "  [ ] seven frozen traits byte-stable"
echo "  [ ] new backend = one crate + inventory::submit!"
