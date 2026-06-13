//! Regression: KH C10 — the AVX2 entropy path emits FMA3, so the runtime
//! dispatch must require `fma` in addition to `avx2` (else SIGILL on an
//! AVX2-without-FMA CPU/VM).
//!
//! Root cause (the bug this locks against): the vectorized AVX2 reduction in
//! `entropy::fast_x86::shannon_entropy_avx2` / `approx_log2_pd` is declared
//! `#[target_feature(enable = "avx2,fma")]` and emits `_mm256_fmadd_pd`
//! (VFMADD231PD, an FMA3 instruction). The earlier dispatch in
//! `entropy::fast::shannon_entropy_simd` gated that call on only
//! `is_x86_feature_detected!("avx2")`. On a CPU/VM that has AVX2 but NOT FMA3
//! (e.g. AMD Piledriver lineage without FMA3, or a hypervisor that masks FMA
//! while leaving AVX2 visible), the gate would let the FMA3-emitting path run
//! and the process would trap with SIGILL on the first `vfmadd231pd`.
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

use keyhog_scanner::entropy::fast::{
    has_high_entropy_fast, shannon_entropy_scalar, shannon_entropy_simd,
};

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
    // Positive direction of the fast gate: the blob's distinct-byte ceiling is
    // log2(256) = 8.0, far above 4.5, so the early-exit must NOT short-circuit
    // and the verdict must be "high entropy".
    assert!(
        has_high_entropy_fast(&blob, 4.5),
        "near-uniform 256-symbol blob must read as high entropy"
    );
}

#[test]
fn fast_gate_negative_twin_short_circuits_below_ceiling() {
    // Negative twin: 8 distinct symbols cap entropy at log2(8) = 3.0 bits/byte,
    // so a threshold strictly above the ceiling must be rejected by the sound
    // early-exit without consulting the (FMA-emitting) reduction at all. This
    // also exercises the >255 active-length size on the low-entropy side.
    let buf: Vec<u8> = (0..1000u32).map(|i| (i % 8) as u8).collect();
    assert!(
        !has_high_entropy_fast(&buf, 3.5),
        "8-symbol buffer (ceiling 3.0) must be short-circuited below 3.5"
    );
    // Comfortably under the ceiling and clear of polynomial drift: still high.
    assert!(
        has_high_entropy_fast(&buf, 2.5),
        "8-symbol buffer (ceiling 3.0) must read high at 2.5"
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

const DISPATCH_SRC: &str = include_str!("../src/entropy/fast.rs");
const AVX2_IMPL_SRC: &str = include_str!("../src/entropy/fast_x86.rs");

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
    // Establishes the premise: the AVX2 reduction really does opt into FMA3 (and
    // therefore really can emit VFMADD231PD). Both the entropy function and its
    // log2 helper must carry it.
    let occurrences = AVX2_IMPL_SRC
        .matches("#[target_feature(enable = \"avx2,fma\")]")
        .count();
    assert!(
        occurrences >= 2,
        "expected the AVX2 entropy fn and its log2 helper to both declare \
         target_feature avx2,fma; found {occurrences} declaration(s)"
    );
    // And it actually emits the FMA3 op, so the gate's `fma` requirement is real.
    assert!(
        AVX2_IMPL_SRC.contains("_mm256_fmadd_pd"),
        "AVX2 reduction must emit _mm256_fmadd_pd (the FMA3 op the gate guards)"
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
