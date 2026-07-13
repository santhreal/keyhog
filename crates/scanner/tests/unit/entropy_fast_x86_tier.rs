//! x86 SIMD entropy-tier dispatch (`entropy/fast.rs`), reached via the
//! `keyhog_scanner::testing::entropy_fast` facade. Migrated from an inline
//! `#[cfg(all(test, target_arch = "x86_64"))] mod x86_tier_tests` to satisfy the
//! `entropy_fast_no_inline_tests` gate. The whole module is x86-only, matching
//! the source (the tier resolver and `X86EntropyTier` exist only on x86_64).
#![cfg(target_arch = "x86_64")]

use keyhog_scanner::testing::entropy_fast::{
    shannon_entropy_scalar, shannon_entropy_simd, x86_entropy_tier_stability,
};

#[test]
fn tier_resolves_once_to_a_stable_known_variant() {
    // The tier is resolved from `cpuid` exactly once and cached: two calls must
    // return the identical variant (the OnceLock never re-detects), and it must
    // be one of the three known tiers.
    let (stable, known) = x86_entropy_tier_stability();
    assert!(stable, "cached tier must be stable across calls");
    assert!(
        known,
        "resolved tier must be a known variant (Avx512/Avx2/Scalar)"
    );
}

#[test]
fn dispatched_tier_matches_scalar_reduction_to_ulps() {
    // Whichever SIMD tier this CPU selects, its reduction must agree with the
    // exact scalar reference to within a few ULPs, the histogram and the `log2`
    // reduction are shared owners, so the only divergence allowed is floating-point
    // rounding. Asserts concrete entropy relationships, not `!is_empty`.
    let cases: [&[u8]; 4] = [
        b"aaaaaaaaaaaaaaaaaaaaaaaa",
        b"The quick brown fox jumps over the lazy dog 0123456789",
        b"\x00\x00\x00\x00\x00\x00\x00\x00deadbeefcafef00dfeedface",
        b"9f8e7d6c5b4a39281706fedcba0987654321abcdef01234567",
    ];
    for data in cases {
        let dispatched = shannon_entropy_simd(data);
        let scalar = shannon_entropy_scalar(data);
        assert!(
            (dispatched - scalar).abs() < 1e-9,
            "simd {dispatched} vs scalar {scalar} for {data:?}"
        );
    }
    // A uniform buffer carries zero entropy; a wide, near-uniform hex spread sits
    // well above the 4.5 high floor (pin both ends through the dispatch).
    assert_eq!(shannon_entropy_simd(b"AAAAAAAAAAAAAAAA"), 0.0);
    assert!(shannon_entropy_simd(b"9f8e7d6c5b4a39281706fedcba098765") > 3.5);
}
