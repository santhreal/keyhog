//! Regression coverage for the entropy fast-path findings:
//!
//! * KH C10 / M9 — runtime SIMD dispatch must require every feature the wide
//!   path actually emits (AVX2 path emits FMA3; AVX-512 path emits an AVX512DQ
//!   convert). The fix tightened the probe in `shannon_entropy_simd`; this test
//!   exercises the long (>255-byte) reduction path on the host's real dispatch
//!   and asserts it returns a correct value instead of executing an illegal
//!   instruction (SIGILL).
//!
//! * KH M11 — `has_high_entropy_fast` used to short-circuit to `false` from a
//!   tiny non-representative sample (12 scalar bytes / 16 middle SIMD bytes),
//!   producing a false negative when the sampled positions were a constant run
//!   over a high-entropy remainder, and making the scalar and SIMD builds
//!   disagree. The fix counts distinct bytes over the FULL buffer and only
//!   short-circuits below the information-theoretic ceiling.

use keyhog_scanner::testing::entropy_fast::{has_high_entropy_fast, shannon_entropy_scalar};

/// Build the exact M11 failing input: a 1024-byte buffer that is the constant
/// byte 0x41 ('A') at the positions the old samplers looked at (first 4, the
/// 16-byte middle window, last 4) but filled with 256 cycling distinct byte
/// values everywhere else, giving a true Shannon entropy near 8 bits/byte.
fn constant_sampled_high_entropy_remainder() -> Vec<u8> {
    let len = 1024usize;
    let mut buf: Vec<u8> = (0..len).map(|i| (i % 256) as u8).collect();

    let stamp_const = |b: &mut [u8], lo: usize, hi: usize| {
        for x in b.iter_mut().take(hi).skip(lo) {
            *x = 0x41;
        }
    };
    // first 4 (scalar sample) and last 4 (scalar sample)
    stamp_const(&mut buf, 0, 4);
    stamp_const(&mut buf, len - 4, len);
    // middle window covering both the scalar mid..mid+4 and the SSE2 mid-8..mid+8
    let mid = len / 2;
    stamp_const(&mut buf, mid - 8, mid + 8);
    buf
}

#[test]
fn high_entropy_remainder_behind_constant_sample_is_not_false_negative() {
    let buf = constant_sampled_high_entropy_remainder();

    // Ground truth: the whole buffer is high entropy regardless of the sampled
    // positions. The fast check must agree (the old sampler returned false).
    let truth = shannon_entropy_scalar(&buf);
    assert!(
        truth >= 4.5,
        "fixture must be genuinely high entropy, got {truth}"
    );
    assert!(
        has_high_entropy_fast(&buf, 4.5),
        "fast check wrongly skipped a high-entropy buffer hidden behind a constant sample"
    );
}

#[test]
fn fast_check_agrees_with_full_entropy_across_thresholds() {
    // The early-exit must never disagree with the full computation: whenever it
    // returns false, the exact entropy must truly be below the threshold; and
    // it must never short-circuit away a buffer that meets it. This couples the
    // (possibly SIMD) fast path to the scalar ground truth, catching cross-tier
    // sample divergence (M11) on whatever ISA tier the host runs.
    let cases: [Vec<u8>; 4] = [
        constant_sampled_high_entropy_remainder(),
        // Genuinely low entropy: two symbols only (ceiling log2(2) = 1.0 bit).
        std::iter::repeat([0x00u8, 0xFFu8])
            .flatten()
            .take(512)
            .collect(),
        // Single constant byte: zero entropy.
        vec![0x7Au8; 300],
        // Cycling 16 distinct symbols: ceiling log2(16) = 4.0 bits.
        (0..512u32).map(|i| (i % 16) as u8).collect(),
    ];

    for buf in &cases {
        let exact = shannon_entropy_scalar(buf);
        for &threshold in &[1.585f64, 2.0, 4.0, 4.5, 5.8] {
            // The >255-byte SIMD reduction uses a polynomial log2 that can differ
            // from exact by up to ~0.09 bits across CPU tiers (KH M10, not fixed
            // here): a buffer whose exact entropy sits on the knife-edge of the
            // threshold may legitimately flip the SIMD verdict. Only assert the
            // M11 property (full-buffer soundness, no sample-driven false
            // negative) where the exact value is unambiguously on one side.
            if (exact - threshold).abs() <= 0.1 {
                continue;
            }
            let fast = has_high_entropy_fast(buf, threshold);
            let exact_meets = exact >= threshold;
            assert_eq!(
                fast,
                exact_meets,
                "fast/exact disagree: len={} exact={exact} threshold={threshold} fast={fast}",
                buf.len()
            );
        }
    }
}

#[test]
fn long_high_entropy_blob_does_not_sigill_and_is_correct() {
    // >255 active bytes forces the polynomial reduction in whichever SIMD tier
    // the host dispatches to (AVX-512 / AVX2 / SSE2 / scalar). With the tightened
    // feature probe (C10/M9) this must complete instead of trapping, and the
    // value must be sane for a near-uniform high-entropy blob.
    let blob: Vec<u8> = (0..400u32).map(|i| (i % 256) as u8).collect();
    let h = keyhog_scanner::testing::entropy_fast::shannon_entropy_simd(&blob);
    assert!(
        h.is_finite() && h > 6.0,
        "long high-entropy blob produced implausible entropy {h}"
    );
    // The fast gate over the same blob must report it as high entropy.
    assert!(has_high_entropy_fast(&blob, 4.5));
}

#[test]
fn distinct_byte_ceiling_short_circuits_soundly() {
    // A buffer using exactly N distinct symbols cannot exceed log2(N) bits/byte,
    // so the fast check must short-circuit to false for any threshold above that
    // ceiling without consulting the (more expensive) full reduction.
    // 8 distinct symbols => ceiling = log2(8) = 3.0 bits.
    let buf: Vec<u8> = (0..1000u32).map(|i| (i % 8) as u8).collect();
    assert!(
        !has_high_entropy_fast(&buf, 3.5),
        "8-symbol buffer cannot reach 3.5 bits but was not short-circuited"
    );
    // Comfortably under the ceiling (and clear of the ~0.09-bit cross-tier
    // polynomial drift, KH M10) it must still be reported high.
    assert!(has_high_entropy_fast(&buf, 2.5));
}
