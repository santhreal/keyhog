//! Unit tests for the `orchestrator` low-RAM OOM-guard constants. Housed in a
//! sibling `tests.rs` module (rather than an inline `#[cfg(test)] mod {}` block)
//! so the `no_inline_tests_in_src` gate stays green while these still reach the
//! parent module's private constants via `use super::*`.

use super::{
    daemon_requires_gpu, LOW_RAM_HOST_THRESHOLD_MB, LOW_RAM_MAX_DECODE_BYTES,
    LOW_RAM_MAX_MATCHES_PER_CHUNK,
};

/// Pin the OOM-guard thresholds and the 256-KiB decode-window derivation, so
/// a silent edit to any of the three cannot change the low-RAM scan envelope
/// unnoticed.
#[test]
fn low_ram_caps_have_expected_values() {
    assert_eq!(LOW_RAM_HOST_THRESHOLD_MB, 4096);
    assert_eq!(LOW_RAM_MAX_MATCHES_PER_CHUNK, 500);
    assert_eq!(LOW_RAM_MAX_DECODE_BYTES, 256 * 1024);
}

/// The caps are applied via `.min()`, i.e. they clamp DOWN and never raise a
/// smaller configured value, the exact semantics the low-RAM adaptation
/// relies on. Prove both directions with the named constants.
#[test]
fn low_ram_caps_clamp_down_never_up() {
    // Above the cap: reduced to the cap.
    assert_eq!(4096usize.min(LOW_RAM_MAX_MATCHES_PER_CHUNK), 500);
    assert_eq!(
        (4 * 1024 * 1024usize).min(LOW_RAM_MAX_DECODE_BYTES),
        256 * 1024
    );
    // Below the cap: left untouched.
    assert_eq!(100usize.min(LOW_RAM_MAX_MATCHES_PER_CHUNK), 100);
    assert_eq!((64 * 1024usize).min(LOW_RAM_MAX_DECODE_BYTES), 64 * 1024);
}

#[test]
fn daemon_gpu_warmup_follows_the_selected_routing_mode() {
    use keyhog_scanner::ScanBackend;

    assert!(daemon_requires_gpu(None, true).expect("auto policy"));
    assert!(!daemon_requires_gpu(None, false).expect("auto policy"));
    assert!(daemon_requires_gpu(Some(ScanBackend::Gpu), true).expect("gpu policy"));
    assert!(daemon_requires_gpu(Some(ScanBackend::Gpu), false).expect("gpu policy"));
    assert!(!daemon_requires_gpu(Some(ScanBackend::SimdCpu), true).expect("simd policy"));
    assert!(!daemon_requires_gpu(Some(ScanBackend::CpuFallback), true).expect("cpu policy"));
}
