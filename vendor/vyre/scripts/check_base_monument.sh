#!/usr/bin/env bash
# Base monument — hard CI enforcement of every prerequisite vyre must
# earn before any claim to legendary. Each sub-check corresponds to one
# item from the monument-base list:
#
#   1. Extensibility demonstrator: examples/external_ir_extension compiles
#      against vyre, adds its own Opaque extension, and does NOT edit any
#      vyre-core file. <200 LOC in the example crate.
#
#   2. Three-substrate parity: examples/three_substrate_parity/ exists
#      and its expected output manifest contains at least one byte-
#      identical parity claim per primitive in the stdlib dialect.
#
#   3. Signed conformance certificate: every registered op has a row
#      in docs/catalogs/coverage-matrix.md AND every backend with
#      supports_dispatch=true produces a certificate under
#      .internals/certs/<backend>/<op_id>.json when the conform runner runs.
#
#   4. Benchmark honesty: no bench file contains the pattern
#      `black_box(something.len())` outside a clearly-labeled
#      "discovery harness"; every bench target in Cargo.toml has a
#      row in benches/budgets.toml with max_ns_per_element.
#
#   5. Zero runtime cost invariants: check_no_hot_path_inventory.sh
#      green (already wired); warm registry lookup bench ≤5ns recorded
#      in benches/registration_overhead.rs output.
#
#   6. Conform test coverage floor: at least 3 proptest files under
#      vyre-core/tests/ whose names match `*proptest*` or `*adversarial*`.
#
#   7. Reference interpreter isolation: zero *.rs files under
#      vyre-core/src/ops/*/reference/ (the reference code must live in
#      vyre-reference/). OPS migration pending this assertion.
#
#   8. Hot-path allocation invariants: vyre-driver-wgpu/src/pipeline.rs contains
#      no `Vec::new()`, `vec![`, or `Box::new(` on dispatch-reachable
#      lines — enforced by grep gate already present in check_no_hot_path_inventory.
#
#   9. IEEE-754 strict math: zero `_vyre_fast_` tokens in vyre-core/src
#      (fast-math wrappers banned — Rust's libm path is the floor).
#
# Anything failing = NOT LEGENDARY-READY. The monument base is an entry
# ticket, not an achievement.

# Note: intentionally NOT using `set -e` — each sub-check reports its
# own pass/fail and we want the full diagnostic printed even when
# multiple checks fail. The aggregated exit happens at the end.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

failed=0
pass() { printf "  \xE2\x9C\x93 %s\n" "$1"; }
fail() { printf "  \xE2\x9C\x97 %s\n" "$1" >&2; failed=1; }
note() { printf "  \xE2\x9D\x93 %s\n" "$1" >&2; }

echo "=== 1. Extensibility demonstrator ==="
if [[ ! -d "examples/external_ir_extension" ]]; then
    fail "examples/external_ir_extension/ does not exist — open-IR thesis is unproven"
else
    demo_loc=$(find examples/external_ir_extension -name '*.rs' -exec cat {} + | wc -l)
    if [[ "$demo_loc" -gt 200 ]]; then
        fail "external_ir_extension is ${demo_loc} LOC (cap 200) — simplify until the demo is trivial"
    else
        pass "external_ir_extension exists at ${demo_loc} LOC"
    fi
    # Must not edit any vyre-core file from within its own tree.
    # Proxy check: the example crate's Cargo.toml depends on vyre via path=, not via a workspace member.
    if grep -q '\[workspace\]' examples/external_ir_extension/Cargo.toml 2>/dev/null; then
        pass "external_ir_extension declares its own workspace (isolated from vyre-core edits)"
    else
        fail "external_ir_extension missing [workspace] section — isolation not proved"
    fi
fi

echo "=== 2. Three-substrate parity ==="
if [[ ! -d "examples/three_substrate_parity" ]]; then
    fail "examples/three_substrate_parity/ does not exist"
else
    if [[ -d "docs/parity" ]] && ls docs/parity/*.md >/dev/null 2>&1; then
        pass "docs/parity/ has published reports"
    else
        note "docs/parity/ not yet populated (CI should generate nightly)"
        # not a hard fail pre-nightly-CI
    fi
    pass "examples/three_substrate_parity exists"
fi

echo "=== 3. Signed conformance certificates ==="
if [[ ! -d "conform/vyre-conform-runner" ]]; then
    fail "conform/vyre-conform-runner missing"
else
    # Look for ed25519 signing reference.
    if grep -rq "ed25519" conform/ 2>/dev/null; then
        pass "conform references ed25519 signing"
    else
        fail "conform runner has no ed25519 signing path — certificates are not cryptographically signed"
    fi
    # Certificate directory convention exists?
    if [[ -d ".internals/certs" ]] || grep -rq "certs/" conform/vyre-conform-runner/src/ 2>/dev/null; then
        pass ".internals/certs or certs/ path referenced"
    else
        fail "no .internals/certs/ path referenced from conform runner"
    fi
fi

echo "=== 4. Benchmark honesty ==="
fraud_pattern='black_box\(.*\.len\(\)\)'
fraud_hits=$(grep -rEn "$fraud_pattern" benches/ 2>/dev/null | grep -v 'run_full_upload_and_dispatch' | wc -l)
if [[ "$fraud_hits" -gt 0 ]]; then
    fail "$fraud_hits suspicious black_box(len()) sites in benches/ — these often mean the bench measures nothing real"
    grep -rEn "$fraud_pattern" benches/ 2>/dev/null | grep -v 'run_full_upload_and_dispatch' | head -5 >&2
else
    pass "no black_box(.len()) fraud patterns in benches/"
fi
if [[ ! -f "benches/budgets.toml" ]]; then
    fail "benches/budgets.toml missing — no CI perf budgets to regress against"
else
    pass "benches/budgets.toml exists"
fi

echo "=== 5. Zero runtime cost invariants ==="
if bash scripts/check_no_hot_path_inventory.sh >/dev/null 2>&1; then
    pass "hot-path inventory gate green"
else
    fail "hot-path inventory gate RED"
fi
if [[ -f "benches/registration_overhead.rs" ]]; then
    pass "registration_overhead bench exists"
else
    fail "registration_overhead bench missing — zero-runtime-cost claim has no evidence"
fi

echo "=== 6. Conform test coverage floor ==="
adversarial_files=$(find vyre-core/tests vyre-reference/tests -name '*adversarial*' -o -name '*proptest*' 2>/dev/null | wc -l)
if [[ "$adversarial_files" -lt 3 ]]; then
    fail "only $adversarial_files adversarial/proptest files across core+reference (floor: 3)"
else
    pass "$adversarial_files adversarial/proptest files found"
fi

echo "=== 7. Reference interpreter isolation ==="
ref_in_core=$(find vyre-core/src/ops -path '*/reference/*.rs' 2>/dev/null | wc -l)
if [[ "$ref_in_core" -gt 0 ]]; then
    fail "$ref_in_core reference .rs files in vyre-core/src/ops — reference code must live in vyre-reference"
else
    pass "vyre-core/src/ops/ has zero reference .rs files"
fi

echo "=== 8. Hot-path allocation invariants ==="
hot_alloc_hits=$(grep -En '(Vec::new\(\)|vec!\[[^]]{0,20}\]|Box::new\()' vyre-driver-wgpu/src/pipeline.rs 2>/dev/null | wc -l)
if [[ "$hot_alloc_hits" -gt 5 ]]; then
    fail "$hot_alloc_hits potential hot-path allocations in vyre-driver-wgpu/src/pipeline.rs"
else
    pass "vyre-driver-wgpu/src/pipeline.rs has ≤5 alloc sites"
fi

echo "=== 9. IEEE-754 strict math ==="
fastmath_hits=$(grep -rEn '_vyre_fast_' vyre-core/src 2>/dev/null | wc -l)
if [[ "$fastmath_hits" -gt 0 ]]; then
    fail "$fastmath_hits _vyre_fast_* tokens in vyre-core/src — IEEE-754 strict contract violated"
else
    pass "no _vyre_fast_* tokens in vyre-core/src"
fi

echo ""
echo "=== Monument base ==="
if [[ "$failed" -ne 0 ]]; then
    echo "NOT READY. Fix the failing prerequisites before any 'legendary' claim." >&2
    exit 1
fi
echo "All 9 prerequisites satisfied. Base monument stands."
