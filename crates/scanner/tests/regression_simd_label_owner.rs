//! Regression: `hw_probe::simd_label` is the SINGLE owner of the SIMD-tier
//! label precedence chain `"AVX-512" > "AVX2" > "NEON" > "scalar"`.
//!
//! The startup banner, `keyhog backend`, `keyhog doctor`, and the backend store
//! all render the same CPU-feature tier label, so the precedence lives in ONE
//! place (`hw_probe::simd_label`) and every caller re-points at it. These tests
//! pin the EXACT `&'static str` returned for all 8 boolean combinations of
//! `(has_avx512, has_avx2, has_neon)` and prove that `startup_banner` embeds the
//! owner's output verbatim, so a second divergent copy of the chain cannot
//! reappear without turning this file red.

use keyhog_scanner::hw_probe::{simd_label, startup_banner, HardwareCaps};

// ---------------------------------------------------------------------------
// Exhaustive owner truth table: all 8 combos of (avx512, avx2, neon).
// Every assertion is an exact &'static str.
// ---------------------------------------------------------------------------

#[test]
fn label_none_is_scalar() {
    // (F, F, F): no vector ISA available at all.
    assert_eq!(simd_label(false, false, false), "scalar");
}

#[test]
fn label_neon_only() {
    // (F, F, T): aarch64 baseline.
    assert_eq!(simd_label(false, false, true), "NEON");
}

#[test]
fn label_avx2_only() {
    // (F, T, F): typical x86_64 without AVX-512.
    assert_eq!(simd_label(false, true, false), "AVX2");
}

#[test]
fn label_avx2_wins_over_neon() {
    // (F, T, T): both mid bits set -> AVX2 outranks NEON.
    assert_eq!(simd_label(false, true, true), "AVX2");
}

#[test]
fn label_avx512_only() {
    // (T, F, F): high-end server CPU.
    assert_eq!(simd_label(true, false, false), "AVX-512");
}

#[test]
fn label_avx512_wins_over_neon() {
    // (T, F, T): avx512 dominates even if a stray neon bit is set.
    assert_eq!(simd_label(true, false, true), "AVX-512");
}

#[test]
fn label_avx512_wins_over_avx2() {
    // (T, T, F): the common high-end x86_64 case.
    assert_eq!(simd_label(true, true, false), "AVX-512");
}

#[test]
fn label_avx512_wins_over_everything() {
    // (T, T, T): all bits set -> avx512 still wins outright.
    assert_eq!(simd_label(true, true, true), "AVX-512");
}

// ---------------------------------------------------------------------------
// Precedence framed as strict ordering: each higher tier masks all lower bits.
// ---------------------------------------------------------------------------

#[test]
fn avx512_masks_all_lower_bits() {
    // Regardless of the low two bits, avx512 => "AVX-512".
    for avx2 in [false, true] {
        for neon in [false, true] {
            assert_eq!(
                simd_label(true, avx2, neon),
                "AVX-512",
                "avx512=true must always yield AVX-512 (avx2={avx2}, neon={neon})"
            );
        }
    }
}

#[test]
fn avx2_masks_neon_when_no_avx512() {
    // Without avx512, avx2 => "AVX2" whether or not neon is set.
    assert_eq!(simd_label(false, true, false), "AVX2");
    assert_eq!(simd_label(false, true, true), "AVX2");
}

#[test]
fn neon_only_beats_scalar() {
    // Lowest non-scalar tier: neon alone => "NEON", nothing => "scalar".
    assert_eq!(simd_label(false, false, true), "NEON");
    assert_eq!(simd_label(false, false, false), "scalar");
}

#[test]
fn every_label_is_one_of_the_four_known_strings() {
    // The owner must NEVER emit anything outside the closed set.
    let allowed = ["AVX-512", "AVX2", "NEON", "scalar"];
    for a in [false, true] {
        for b in [false, true] {
            for c in [false, true] {
                let got = simd_label(a, b, c);
                assert!(
                    allowed.contains(&got),
                    "simd_label({a},{b},{c}) = {got:?} escaped the allowed set"
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Caller agreement: startup_banner must embed the owner's label verbatim.
// This is the anti-duplication lock — a second inline chain in banner.rs
// would drift from simd_label and fail here.
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn caps(has_avx512: bool, has_avx2: bool, has_neon: bool) -> HardwareCaps {
    HardwareCaps {
        physical_cores: 8,
        logical_cores: 16,
        has_avx2,
        has_avx512,
        has_neon,
        gpu_available: false,
        gpu_name: None,
        gpu_vram_mb: None,
        gpu_runtime_identity: None,
        gpu_is_software: false,
        total_memory_mb: Some(16384),
        io_uring_available: false,
        hyperscan_available: false,
    }
}

#[test]
fn banner_embeds_owner_label_for_all_combos() {
    // For every combo the banner's `SIMD: <x>` segment equals simd_label's output.
    for avx512 in [false, true] {
        for avx2 in [false, true] {
            for neon in [false, true] {
                let c = caps(avx512, avx2, neon);
                let expected = simd_label(avx512, avx2, neon);
                let banner = startup_banner(&c, 1, 1);
                assert!(
                    banner.contains(&format!("SIMD: {expected} |")),
                    "banner {banner:?} must carry `SIMD: {expected} |` for \
                     (avx512={avx512}, avx2={avx2}, neon={neon})"
                );
            }
        }
    }
}

#[test]
fn banner_scalar_segment_is_exact() {
    // Negative twin: no vector ISA -> the banner shows the scalar label exactly.
    let c = caps(false, false, false);
    assert_eq!(
        startup_banner(&c, 1, 1),
        "8 cores | GPU: none | SIMD: scalar | AC | 1 detectors (1 patterns)"
    );
}

#[test]
fn banner_avx512_segment_is_exact() {
    // Positive: high tier renders `SIMD: AVX-512` — same owner, full-string pin.
    let c = caps(true, true, false);
    assert_eq!(
        startup_banner(&c, 1, 1),
        "8 cores | GPU: none | SIMD: AVX-512 | AC | 1 detectors (1 patterns)"
    );
}
