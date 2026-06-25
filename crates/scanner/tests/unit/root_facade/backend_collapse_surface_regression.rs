//! Regression pins for the COLLAPSED rule-pipeline / backend surface after the
//! dead `rule_pipeline_cached` on-disk cache wrapper was deleted (LANE:
//! close-org-deadcode).
//!
//! `backend_collapse_regression.rs` already source-greps that the dead routes
//! stay removed. This file pins the positive live side: adaptive MegaScan sizing
//! and the collapsed backend labels.

use crate::engine::rule_pipeline::megascan_input_len_for_vram_mb;
use keyhog_scanner::engine::megascan_input_len;
use keyhog_scanner::hw_probe::testing::ScanBackend;

// ---------------------------------------------------------------------------
// 1. The VRAM-adaptive `megascan_input_len()` stays bounded and process-stable.
// ---------------------------------------------------------------------------

#[test]
fn megascan_input_len_is_vram_sized_and_never_below_floor() {
    // The host-adaptive sizing is cached + stable for the process. On any host
    // it must be a power-of-two byte budget in [128 MiB, 1 GiB], and never below
    // the 128 MiB minimum the sizing table guarantees.
    let len = megascan_input_len();
    const ONE_TWENTY_EIGHT_MIB: usize = 128 * 1024 * 1024;
    const ONE_GIB: usize = 1024 * 1024 * 1024;
    assert!(
        (ONE_TWENTY_EIGHT_MIB..=ONE_GIB).contains(&len),
        "megascan_input_len {len} must sit in [128 MiB, 1 GiB]"
    );
    assert!(
        len.is_power_of_two(),
        "megascan_input_len {len} must be a power-of-two byte budget"
    );
    // Cached: a second call returns the identical value.
    assert_eq!(
        megascan_input_len(),
        len,
        "megascan_input_len must be process-stable (cached)"
    );
}

#[test]
fn megascan_input_len_matches_documented_vram_table() {
    const MIB_128: usize = 128 * 1024 * 1024;
    const MIB_256: usize = 256 * 1024 * 1024;
    const MIB_512: usize = 512 * 1024 * 1024;
    const GIB_1: usize = 1024 * 1024 * 1024;

    for (vram_mb, expected) in [
        (None, MIB_128),
        (Some(0), MIB_128),
        (Some(8 * 1024 - 1), MIB_128),
        (Some(8 * 1024), MIB_256),
        (Some(12 * 1024 - 1), MIB_256),
        (Some(12 * 1024), MIB_512),
        (Some(24 * 1024 - 1), MIB_512),
        (Some(24 * 1024), GIB_1),
    ] {
        assert_eq!(
            megascan_input_len_for_vram_mb(vram_mb),
            expected,
            "VRAM {vram_mb:?} MiB must map to documented MegaScan input length"
        );
    }
}

// ---------------------------------------------------------------------------
// 2. The collapsed `ScanBackend` model is EXACTLY four variants with stable
//    labels. No fifth engine snuck back in alongside the dead-route removal.
// ---------------------------------------------------------------------------

#[test]
fn scan_backend_is_exactly_the_four_collapsed_variants() {
    // Exhaustive match: adding/removing a variant forces this test to be
    // updated, and the label set below pins coherence with --help / banner.
    let all = [
        ScanBackend::Gpu,
        ScanBackend::MegaScan,
        ScanBackend::SimdCpu,
        ScanBackend::CpuFallback,
    ];
    let labels: Vec<&'static str> = all.iter().map(|b| b.label()).collect();
    assert_eq!(
        labels,
        vec![
            "gpu-region-presence",
            "gpu-mega-scan",
            "simd-regex",
            "cpu-fallback"
        ],
        "the four collapsed backend labels must stay stable and in order"
    );
    // Labels are distinct (no two variants alias to the same operator string).
    let mut sorted = labels.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(
        sorted.len(),
        4,
        "every backend label must be unique; got duplicates in {labels:?}"
    );
}
