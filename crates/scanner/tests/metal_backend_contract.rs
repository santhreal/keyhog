//! Contract tests for the native Apple Metal scan backend.
//!
//! Metal is a distinct persisted autoroute peer. These tests prevent it from
//! collapsing into the portable WGPU route or disappearing from CLI parsing.

use keyhog_scanner::hw_probe::{parse_backend_str, BACKEND_OVERRIDE_VALUES};
use keyhog_scanner::ScanBackend;

/// Locks the stable label used by autoroute evidence, diagnostics, and daemon receipts.
#[test]
fn metal_backend_has_a_distinct_stable_label() {
    assert_eq!(ScanBackend::GpuMetal.label(), "gpu-metal-region-presence");
    assert_ne!(ScanBackend::GpuMetal.label(), ScanBackend::GpuWgpu.label());
    assert_ne!(ScanBackend::GpuMetal.label(), ScanBackend::GpuCuda.label());
}

/// Prevents native Metal from bypassing GPU accounting and GPU-majority enforcement.
#[test]
fn metal_backend_is_classified_as_gpu() {
    assert!(ScanBackend::GpuMetal.is_gpu());
}

/// Proves every supported Metal spelling selects Metal instead of silently selecting autoroute.
#[test]
fn metal_backend_operator_spellings_parse_exactly() {
    for spelling in [
        "gpu-metal-region-presence",
        "gpu-metal",
        "  GPU-METAL  ",
        "  GpU-MeTaL  ",
    ] {
        assert_eq!(
            parse_backend_str(spelling),
            Some(ScanBackend::GpuMetal),
            "Metal spelling {spelling:?} must select the native Metal peer"
        );
    }
}

/// Keeps the forced Metal route discoverable through the CLI value list.
#[test]
fn metal_backend_is_advertised_as_an_override() {
    assert!(BACKEND_OVERRIDE_VALUES.contains(&"gpu-metal"));
}

/// Prevents ambiguous or implementation-shaped strings from selecting Metal accidentally.
#[test]
fn unsupported_metal_spellings_fail_closed() {
    for spelling in ["mlx", "gpu-mlx", "metal", "metal-gpu", "apple-gpu", "metal-region"] {
        assert_eq!(
            parse_backend_str(spelling),
            None,
            "unsupported spelling {spelling:?} must not select a backend"
        );
    }
}
