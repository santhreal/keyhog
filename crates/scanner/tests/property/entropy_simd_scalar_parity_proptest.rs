//! SIMD ↔ scalar Shannon-entropy parity (`crates/scanner/src/entropy/**`).
//!
//! The entropy reduction has a scalar reference (`shannon_entropy_scalar`) and
//! AVX2 / AVX-512 / NEON specializations. They all count through the one
//! `histogram_8way` null contract, but each SIMD path specializes the 256-bin
//! log2 summation — the exact place a floating-point or formula divergence can
//! creep in. Law 8 makes SIMD/scalar parity non-optional: a fast path that
//! disagrees with the scalar oracle is a correctness bug, not an acceptable
//! speed trade. The two branches of `entropy_from_histogram` (KH-28 table
//! lookup for `active_len <= 255`, direct `-Σ p·log2 p` above) are BOTH swept.
//!
//! Each `#[target_feature]` path is invoked only when the running CPU actually
//! carries its features (the `*_if_supported` accessors return `None`
//! otherwise), so this never calls an illegal intrinsic — but on a CPU that
//! DOES carry AVX2/AVX-512 the parity assertion runs for real (no silent skip).

#[cfg(target_arch = "x86_64")]
use keyhog_scanner::testing::{
    shannon_entropy_avx2_if_supported_for_test, shannon_entropy_avx512_if_supported_for_test,
};
use keyhog_scanner::testing::{shannon_entropy_scalar_for_test, shannon_entropy_simd_for_test};
use proptest::prelude::*;

/// Entropy values live in `[0, 8]`; summation-order differences across SIMD
/// lanes bound the disagreement well under `1e-12`. A relative+absolute `1e-9`
/// tolerance is generous yet still catches a genuine formula divergence (which
/// would be `O(0.1)` bits, not `O(1e-13)`).
const EPS: f64 = 1e-9;

fn close(a: f64, b: f64) -> bool {
    (a - b).abs() <= EPS * (1.0 + a.abs().max(b.abs()))
}

// ── deterministic oracle + structural edge cases ─────────────────────────────

#[test]
fn scalar_oracle_hits_known_reference_values() {
    // A single distinct byte carries zero entropy; 256 distinct bytes carry
    // exactly log2(256) = 8 bits/byte. These pin the oracle itself, so the
    // parity proptests below are comparing against a correct reference.
    assert_eq!(shannon_entropy_scalar_for_test(&[0x41; 100]), 0.0);
    let all_distinct: Vec<u8> = (0..=255u8).collect();
    assert!(
        (shannon_entropy_scalar_for_test(&all_distinct) - 8.0).abs() < 1e-12,
        "256 distinct bytes must be exactly 8 bits/byte, got {}",
        shannon_entropy_scalar_for_test(&all_distinct)
    );
}

#[test]
fn every_path_agrees_on_structural_edge_cases() {
    let cases: Vec<Vec<u8>> = vec![
        vec![],                                       // empty → 0.0
        vec![0u8; 64],                                // all-null → padding-skipped → 0.0
        vec![0x5au8; 1],                              // one byte → 0.0
        vec![0x5au8; 1000],                           // one distinct byte, large → 0.0
        (0..=255u8).collect(),                        // all distinct → 8.0
        (0..4096).map(|i| (i % 256) as u8).collect(), // uniform over 256, large
        (0..300).map(|i| (i % 2) as u8).collect(),    // two symbols → 1.0 bit
    ];
    for case in &cases {
        let scalar = shannon_entropy_scalar_for_test(case);
        let simd = shannon_entropy_simd_for_test(case);
        assert!(
            close(scalar, simd),
            "dispatch parity: simd {simd} vs scalar {scalar} (len {})",
            case.len()
        );
        #[cfg(target_arch = "x86_64")]
        {
            if let Some(avx2) = shannon_entropy_avx2_if_supported_for_test(case) {
                assert!(
                    close(scalar, avx2),
                    "avx2 {avx2} vs scalar {scalar} (len {})",
                    case.len()
                );
            }
            if let Some(avx512) = shannon_entropy_avx512_if_supported_for_test(case) {
                assert!(
                    close(scalar, avx512),
                    "avx512 {avx512} vs scalar {scalar} (len {})",
                    case.len()
                );
            }
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4_000))]

    /// The once-dispatched `shannon_entropy_simd` (whatever tier this CPU chose)
    /// must equal the scalar reference on ANY input.
    #[test]
    fn simd_dispatch_matches_scalar(bytes in prop::collection::vec(any::<u8>(), 0..512)) {
        let scalar = shannon_entropy_scalar_for_test(&bytes);
        let simd = shannon_entropy_simd_for_test(&bytes);
        prop_assert!(
            close(scalar, simd),
            "simd {} vs scalar {} for len {}", simd, scalar, bytes.len()
        );
    }

    /// The AVX2 path, where available, matches the scalar oracle exactly (within
    /// FP tolerance). Skipped on a non-AVX2 CPU (accessor returns `None`).
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn avx2_matches_scalar(bytes in prop::collection::vec(any::<u8>(), 0..512)) {
        if let Some(avx2) = shannon_entropy_avx2_if_supported_for_test(&bytes) {
            let scalar = shannon_entropy_scalar_for_test(&bytes);
            prop_assert!(
                close(scalar, avx2),
                "avx2 {} vs scalar {} for len {}", avx2, scalar, bytes.len()
            );
        }
    }

    /// The AVX-512 path, where available, matches the scalar oracle.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn avx512_matches_scalar(bytes in prop::collection::vec(any::<u8>(), 0..512)) {
        if let Some(avx512) = shannon_entropy_avx512_if_supported_for_test(&bytes) {
            let scalar = shannon_entropy_scalar_for_test(&bytes);
            prop_assert!(
                close(scalar, avx512),
                "avx512 {} vs scalar {} for len {}", avx512, scalar, bytes.len()
            );
        }
    }

    /// The KH-28 small-input branch (`active_len <= 255`, table-lookup formula)
    /// is the regime most likely to diverge from a naive per-symbol SIMD sum —
    /// sweep it densely.
    #[test]
    fn simd_matches_scalar_on_small_inputs(bytes in prop::collection::vec(any::<u8>(), 0..=255)) {
        let scalar = shannon_entropy_scalar_for_test(&bytes);
        let simd = shannon_entropy_simd_for_test(&bytes);
        prop_assert!(close(scalar, simd), "small-input simd {} vs scalar {}", simd, scalar);
    }

    /// Low-cardinality inputs (few distinct bytes, high per-bin counts) push the
    /// large-count side of the log2 reduction where per-lane accumulation order
    /// matters most.
    #[test]
    fn simd_matches_scalar_on_low_cardinality(
        alphabet in prop::collection::vec(any::<u8>(), 1..4),
        len in 1usize..2048,
    ) {
        let bytes: Vec<u8> = (0..len).map(|i| alphabet[i % alphabet.len()]).collect();
        let scalar = shannon_entropy_scalar_for_test(&bytes);
        let simd = shannon_entropy_simd_for_test(&bytes);
        prop_assert!(close(scalar, simd), "low-card simd {} vs scalar {}", simd, scalar);
    }
}
