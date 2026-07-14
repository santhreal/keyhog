//! Unit tests for the `orchestrator` low-RAM OOM-guard constants. Housed in a
//! sibling `tests.rs` module (rather than an inline `#[cfg(test)] mod {}` block)
//! so the `no_inline_tests_in_src` gate stays green while these still reach the
//! parent module's private constants via `use super::*`.

use super::run::{resolve_scan_exit, ScanOutcome};
use super::{
    apply_host_runtime_limits, daemon_requires_gpu, resolved_scan_config_for_scanner,
    setup_default_scan_runtime, LOW_RAM_HOST_THRESHOLD_MB, LOW_RAM_MAX_DECODE_BYTES,
    LOW_RAM_MAX_MATCHES_PER_CHUNK,
};
use crate::exit_codes::{
    EXIT_FINDINGS, EXIT_LIVE_CREDENTIALS, EXIT_SCANNER_PANIC, EXIT_SOURCE_FAILED, EXIT_SUCCESS,
    EXIT_SYSTEM_ERROR,
};

#[test]
fn scan_exit_priority_is_explicit_for_every_terminal_class() {
    for mask in 0_u8..64 {
        let outcome = ScanOutcome {
            autoroute_calibration: mask & 1 != 0,
            scanner_panicked: mask & 2 != 0,
            has_live_credentials: mask & 4 != 0,
            has_new_entries: mask & 8 != 0,
            incremental_cache_failed: mask & 16 != 0,
            source_coverage_incomplete: mask & 32 != 0,
        };
        let expected = if outcome.autoroute_calibration && !outcome.scanner_panicked {
            EXIT_SUCCESS
        } else if outcome.scanner_panicked {
            EXIT_SCANNER_PANIC
        } else if outcome.has_live_credentials {
            EXIT_LIVE_CREDENTIALS
        } else if outcome.has_new_entries {
            EXIT_FINDINGS
        } else if outcome.incremental_cache_failed {
            EXIT_SYSTEM_ERROR
        } else if outcome.source_coverage_incomplete {
            EXIT_SOURCE_FAILED
        } else {
            EXIT_SUCCESS
        };
        assert_eq!(resolve_scan_exit(outcome), expected, "outcome: {outcome:?}");
    }
}

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
fn low_ram_host_limits_mutate_the_resolved_config_shared_by_all_runtimes() {
    let mut scanner = keyhog_scanner::ScannerConfig::default();
    scanner.max_matches_per_chunk = LOW_RAM_MAX_MATCHES_PER_CHUNK * 2;
    scanner.max_decode_bytes = LOW_RAM_MAX_DECODE_BYTES * 2;
    let mut resolved = resolved_scan_config_for_scanner(scanner);
    let hardware = keyhog_scanner::HardwareCaps {
        physical_cores: 4,
        logical_cores: 8,
        has_avx2: false,
        has_avx512: false,
        has_neon: false,
        gpu_available: false,
        gpu_name: None,
        gpu_vram_mb: None,
        gpu_runtime_identity: None,
        gpu_is_software: false,
        total_memory_mb: Some(LOW_RAM_HOST_THRESHOLD_MB - 1),
        io_uring_available: false,
        hyperscan_available: false,
    };

    apply_host_runtime_limits(&mut resolved, &hardware);

    assert_eq!(
        resolved.scanner.max_matches_per_chunk,
        LOW_RAM_MAX_MATCHES_PER_CHUNK
    );
    assert_eq!(resolved.scanner.max_decode_bytes, LOW_RAM_MAX_DECODE_BYTES);
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

#[cfg(feature = "simd")]
#[test]
fn persistent_runtime_uses_configured_autoroute_cache_path() {
    use keyhog_core::{Chunk, ChunkMetadata};

    let root = tempfile::tempdir().expect("tempdir");
    let cache_path = root.path().join("custom-autoroute.json");
    std::fs::write(
        root.path().join(".keyhog.toml"),
        format!(
            "[system]\nautoroute_cache = {:?}\n",
            cache_path.display().to_string()
        ),
    )
    .expect("write config");

    let runtime = setup_default_scan_runtime(
        std::path::Path::new("detectors"),
        false,
        None,
        None,
        None,
        "keyhog watch",
        false,
        Some(root.path()),
    )
    .expect("build persistent runtime");
    let chunk = Chunk {
        data: "plain text".into(),
        metadata: ChunkMetadata {
            source_type: "filesystem".into(),
            size_bytes: Some(10),
            ..ChunkMetadata::default()
        },
    };
    let error = runtime
        .scan_chunk(&chunk)
        .expect_err("an uncalibrated multi-backend runtime must fail closed");

    assert!(
        error
            .to_string()
            .contains(&cache_path.display().to_string()),
        "routing error must name the configured cache path; got {error}"
    );
}
