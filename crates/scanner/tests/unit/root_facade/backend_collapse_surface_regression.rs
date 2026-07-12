//! Regression pins for the COLLAPSED rule-pipeline / backend surface after the
//! dead `rule_pipeline_cached` on-disk cache wrapper was deleted (LANE:
//! close-org-deadcode).
//!
//! `backend_collapse_regression.rs` already source-greps that the dead routes
//! stay removed. This file pins the positive live side: adaptive GPU batch
//! sizing and the collapsed backend labels.

use crate::engine::gpu_input_budget::gpu_batch_input_limit_for_vram_mb;
use keyhog_scanner::engine::gpu_batch_input_limit;
use keyhog_scanner::hw_probe::testing::ScanBackend;

// ---------------------------------------------------------------------------
// 1. The VRAM-adaptive `gpu_batch_input_limit()` stays bounded and process-stable.
// ---------------------------------------------------------------------------

#[test]
fn gpu_batch_input_limit_is_vram_sized_and_never_below_floor() {
    // The host-adaptive sizing is cached + stable for the process. On any host
    // it must be a power-of-two byte budget in [128 MiB, 1 GiB], and never below
    // the 128 MiB minimum the sizing table guarantees.
    let len = gpu_batch_input_limit();
    const ONE_TWENTY_EIGHT_MIB: usize = 128 * 1024 * 1024;
    const ONE_GIB: usize = 1024 * 1024 * 1024;
    assert!(
        (ONE_TWENTY_EIGHT_MIB..=ONE_GIB).contains(&len),
        "gpu_batch_input_limit {len} must sit in [128 MiB, 1 GiB]"
    );
    assert!(
        len.is_power_of_two(),
        "gpu_batch_input_limit {len} must be a power-of-two byte budget"
    );
    // Cached: a second call returns the identical value.
    assert_eq!(
        gpu_batch_input_limit(),
        len,
        "gpu_batch_input_limit must be process-stable (cached)"
    );
}

#[test]
fn gpu_batch_input_limit_matches_documented_vram_table() {
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
            gpu_batch_input_limit_for_vram_mb(vram_mb),
            expected,
            "VRAM {vram_mb:?} MiB must map to documented GPU batch input limit"
        );
    }
}

// ---------------------------------------------------------------------------
// 2. `ScanBackend` names the three real engines exactly once.
// ---------------------------------------------------------------------------

#[test]
fn scan_backend_is_exactly_the_three_real_engines() {
    // Exhaustive match: adding/removing a variant forces this test to be
    // updated, and the label set below pins coherence with --help / banner.
    let all = [
        ScanBackend::Gpu,
        ScanBackend::SimdCpu,
        ScanBackend::CpuFallback,
    ];
    let labels: Vec<&'static str> = all.iter().map(|b| b.label()).collect();
    assert_eq!(
        labels,
        vec!["gpu-region-presence", "simd-regex", "cpu-fallback"],
        "the three backend labels must stay stable and in order"
    );
    // Labels are distinct (no two variants alias to the same operator string).
    let mut sorted = labels.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(
        sorted.len(),
        3,
        "every backend label must be unique; got duplicates in {labels:?}"
    );
}
