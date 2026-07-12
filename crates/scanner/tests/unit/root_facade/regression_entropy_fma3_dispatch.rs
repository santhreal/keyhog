//! Regression: KH C10 — the AVX2 entropy path emits FMA3, so the runtime
//! dispatch must require `fma` in addition to `avx2` (else SIGILL on an
//! AVX2-without-FMA CPU/VM).
//!
//! Root cause (the bug this locks against): the AVX2 entropy reduction in
//! `entropy::fast_x86::shannon_entropy_avx2` is compiled with
//! `#[target_feature(enable = "avx2,fma")]`. Enabling `fma` LICENSES the
//! compiler to emit FMA3 instructions (VFMADD231PD) anywhere in that function —
//! historically via an explicit `_mm256_fmadd_pd` in a vectorized
//! polynomial-log2, and still today via contraction of the reduction's float
//! mul-adds. The earlier dispatch in `entropy::fast::shannon_entropy_simd`
//! gated that call on only `is_x86_feature_detected!("avx2")`. On a CPU/VM that
//! has AVX2 but NOT FMA3 (e.g. AMD Piledriver lineage without FMA3, or a
//! hypervisor that masks FMA while leaving AVX2 visible), the gate would let
//! the FMA3-capable path run and the process would trap with SIGILL on the
//! first `vfmadd231pd`. The decisive, durable invariant is therefore the
//! target_feature DECLARATION, not the presence of any one intrinsic (the
//! polynomial-log2 was since replaced by the bit-exact shared reduction).
//!
//! Why this test is host-independent: a purely behavioral "does it SIGILL?"
//! test only exercises whatever ISA tier the *runner's* CPU dispatches to. On a
//! runner that has FMA (the common case, including AVX-512 hosts that never
//! even enter the AVX2 branch) the buggy `avx2`-only gate would have run fine,
//! so a runtime-only test could never fail against the old code. The decisive,
//! every-host invariant is the *gate contract*: the runtime feature check that
//! dispatches into a `#[target_feature]` function must enable a SUPERSET of the
//! features that function declares. We assert that contract against the dispatch
//! source directly, so the test fails on ANY host if the gate is ever loosened
//! back to `avx2`-only — while the numeric assertions independently lock the
//! reduction's correctness on whatever tier this host actually runs.

use keyhog_scanner::testing::entropy_fast::{shannon_entropy_scalar, shannon_entropy_simd};

/// Deterministic >255-active-byte high-entropy blob: bytes 0,1,...,255,0,1,...143.
/// active_len stays 400 (no fully-null 8-byte chunk: byte 0x00 only ever shares
/// a chunk with non-zero bytes, so the null-padding contract never drops it).
fn long_high_entropy_blob() -> Vec<u8> {
    (0..400u32).map(|i| (i % 256) as u8).collect()
}

/// Exact Shannon entropy of [`long_high_entropy_blob`], computed offline from
/// the same null-contract histogram the code uses (active_len = 400; bytes
/// 0..=143 occur twice, 144..=255 once): H = -Σ p·log2 p. Derived from the
/// source, not guessed.
const EXACT_ENTROPY: f64 = 7.923_856_189_774_735_3;

/// The SIMD long-path (>255) uses a 5-term polynomial log2 that can drift from
/// the exact value by up to ~0.09 bits/byte across CPU tiers (KH M10). Allow
/// that band when asserting against the SIMD dispatch; the scalar path is exact.
const POLY_LOG2_DRIFT: f64 = 0.1;

#[test]
fn scalar_long_path_is_bit_exact() {
    // The scalar reference uses real `f64::log2`, so it must reproduce the
    // hand-derived value exactly. This pins the histogram null-contract and the
    // >255 reduction branch together.
    let blob = long_high_entropy_blob();
    let h = shannon_entropy_scalar(&blob);
    assert_eq!(
        h, EXACT_ENTROPY,
        "scalar >255 reduction drifted from derived exact value"
    );
}

#[test]
fn simd_dispatch_does_not_sigill_and_matches_exact_within_drift() {
    // Forces the >255 polynomial reduction in whichever tier this host
    // dispatches to (AVX-512 / AVX2 / SSE2 / scalar). With the FMA-aware gate
    // this completes instead of trapping, and lands within the documented
    // polynomial drift of the exact value. If the AVX2 path were ever dispatched
    // on a no-FMA host this call would SIGILL and crash the test process.
    let blob = long_high_entropy_blob();
    let h = shannon_entropy_simd(&blob);
    assert!(h.is_finite(), "SIMD entropy must be finite, got {h}");
    assert!(
        (h - EXACT_ENTROPY).abs() <= POLY_LOG2_DRIFT,
        "SIMD entropy {h} is outside the {POLY_LOG2_DRIFT}-bit drift band around exact {EXACT_ENTROPY}"
    );
}

// ---------------------------------------------------------------------------
// Root-cause gate-contract assertions (host-independent).
//
// These read the actual dispatch source and the actual target_feature
// declarations and assert the C10 invariant structurally: the runtime gate that
// dispatches into the AVX2 reduction must require every feature that reduction's
// `#[target_feature]` enables. The pre-fix `avx2`-only gate fails these on every
// host, including AVX-512 hosts that never take the AVX2 branch at runtime.
// ---------------------------------------------------------------------------

const DISPATCH_SRC: &str = include_str!("../../../src/entropy/fast.rs");
const AVX2_IMPL_SRC: &str = include_str!("../../../src/entropy/fast_x86.rs");

/// Extract the body of the `#[cfg(target_arch = "x86_64")]` x86 dispatch
/// `shannon_entropy_simd` so the assertions cannot be satisfied by a comment or
/// the aarch64/generic variants elsewhere in the file.
fn x86_dispatch_body() -> &'static str {
    // The x86 variant is the one guarded by the avx512/avx2/sse2 probes; locate
    // the `is_x86_feature_detected!("avx2")` call and return the line holding it.
    DISPATCH_SRC
        .lines()
        .find(|l| {
            l.contains("is_x86_feature_detected!(\"avx2\")") && !l.trim_start().starts_with("//")
        })
        .expect("x86 dispatch must contain an avx2 feature probe")
}

#[test]
fn avx2_reduction_declares_fma_target_feature() {
    // Establishes the premise that makes the dispatch gate's `fma` requirement
    // load-bearing: the AVX2 reduction is compiled with
    // `#[target_feature(enable = "avx2,fma")]`. That DECLARATION — not any
    // particular intrinsic in the body — is what licenses the compiler to emit
    // FMA3 (VFMADD231PD) anywhere in the function (e.g. contracting the
    // histogram reduction's `count * log2` mul-add), and is therefore what makes
    // *entering* the function on a no-FMA CPU unsound. The reduction itself was
    // deliberately moved to the shared, bit-exact `entropy_from_histogram` and
    // no longer calls an explicit `_mm256_fmadd_pd` (see entropy/fast_x86.rs
    // doc: the old vectorized polynomial-log2 diverged ~5e-3 bits/byte), so the
    // gate contract is anchored on the target_feature declaration — the robust
    // invariant — not on the presence of one intrinsic.
    //
    // Match a REAL attribute line (trimmed, starts with `#[target_feature`), not
    // a doc-comment that merely mentions the attribute string.
    let declares_avx2_fma = AVX2_IMPL_SRC.lines().any(|l| {
        let t = l.trim_start();
        t.starts_with("#[target_feature") && t.contains("avx2") && t.contains("fma")
    });
    assert!(
        declares_avx2_fma,
        "the AVX2 reduction must carry a real #[target_feature(enable = \"avx2,fma\")] \
         attribute — that declaration is what forces the dispatch gate to require fma"
    );
    // And that opt-in must sit on the AVX2 entropy entry point itself, so the
    // gate is guarding the function the runtime actually dispatches into.
    assert!(
        AVX2_IMPL_SRC.contains("fn shannon_entropy_avx2"),
        "the AVX2 reduction entry point shannon_entropy_avx2 must exist in the impl"
    );
}

#[test]
fn avx2_dispatch_gate_requires_fma_not_just_avx2() {
    // THE core regression: the line that dispatches into the FMA3-emitting AVX2
    // path must require BOTH avx2 AND fma. The buggy pre-fix gate read
    //   if is_x86_feature_detected!("avx2") {
    // (no `&& fma`) and would fail this assertion.
    let gate = x86_dispatch_body();
    assert!(
        gate.contains("is_x86_feature_detected!(\"avx2\")"),
        "AVX2 dispatch gate not found"
    );
    assert!(
        gate.contains("is_x86_feature_detected!(\"fma\")"),
        "AVX2 dispatch gate must also require fma (C10: AVX2 path emits FMA3); \
         gate line was: {gate:?}"
    );
    // Both probes must be ANDed on the SAME guard (not an unrelated `||` or a
    // separate statement), so the AVX2 branch is taken only when both hold.
    assert!(
        gate.contains("&&"),
        "avx2 and fma probes must be conjoined on the same dispatch guard; \
         gate line was: {gate:?}"
    );
}

#[test]
fn avx512_dispatch_gate_requires_dq_sibling_invariant() {
    // Sibling of the same C10/M9 contract on the wider tier: the AVX-512
    // reduction emits an AVX512DQ convert (_mm512_cvtepi64_pd), so its gate must
    // require avx512dq alongside avx512f/avx512bw. Locking it here keeps the two
    // wide gates from regressing independently.
    let f = DISPATCH_SRC.contains("is_x86_feature_detected!(\"avx512f\")");
    let bw = DISPATCH_SRC.contains("is_x86_feature_detected!(\"avx512bw\")");
    let dq = DISPATCH_SRC.contains("is_x86_feature_detected!(\"avx512dq\")");
    assert!(
        f && bw && dq,
        "AVX-512 dispatch must require avx512f+avx512bw+avx512dq (have f={f} bw={bw} dq={dq})"
    );
}
