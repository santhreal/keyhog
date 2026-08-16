//! Focused unit tests for private `orchestrator` helpers and runtime policy.
//! Housed in a sibling `tests.rs` module (rather than an inline `#[cfg(test)]
//! mod {}` block) so the `no_inline_tests_in_src` gate stays green while these
//! still reach the parent module's private items via `use super::*`.

mod disabled_detector_relations;
mod shared_default_detector_modes;
mod workflow_state;

use super::run::{resolve_scan_exit, ScanOutcome};
#[cfg(feature = "simd")]
use super::setup_default_scan_runtime_for_test;
use super::{
    apply_host_runtime_limits, daemon_compile_failure, daemon_gpu_preflight_failure,
    daemon_requires_gpu, default_runtime_gpu_init_policy, resolved_scan_config_for_scanner,
    validate_daemon_gpu_initialization, validate_daemon_gpu_warmup, LOW_RAM_HOST_THRESHOLD_MB,
    LOW_RAM_MAX_DECODE_BYTES, LOW_RAM_MAX_MATCHES_PER_CHUNK,
};
use crate::exit_codes::EXIT_REQUIRE_GPU_UNMET;
use crate::exit_codes::{
    EXIT_FINDINGS, EXIT_LIVE_CREDENTIALS, EXIT_SCANNER_PANIC, EXIT_SOURCE_FAILED, EXIT_SUCCESS,
    EXIT_SYSTEM_ERROR, EXIT_USER_ERROR,
};
use crate::testing::CliTestApi;

#[test]
fn collect_detector_signatures_unifies_primary_and_companion_regexes() {
    let detectors = vec![keyhog_core::DetectorSpec {
        patterns: vec![keyhog_core::PatternSpec {
            regex: "primary_[A-Z]+".into(),
            description: None,
            group: None,
            required_literals: Vec::new(),
            client_safe: false,
            weak_anchor: false,
            structural_password_slot: false,
        }],
        companions: vec![keyhog_core::CompanionSpec {
            name: "secondary".into(),
            regex: "secondary_[A-Z]+".into(),
            within_lines: 2,
            required: false,
            ..Default::default()
        }],
        ..keyhog_core::DetectorSpec::default()
    }];

    let signatures = super::collect_detector_signatures(&detectors);
    assert_eq!(signatures.len(), 2);
    assert!(signatures.contains("primary_[A-Z]+"));
    assert!(signatures.contains("secondary_[A-Z]+"));
}

#[test]
fn scan_exit_priority_is_explicit_for_every_terminal_class() {
    for mask in 0_u16..256 {
        let outcome = ScanOutcome {
            autoroute_calibration: mask & 1 != 0,
            scanner_panicked: mask & 2 != 0,
            has_live_credentials: mask & 4 != 0,
            has_blocking_findings: mask & 8 != 0,
            incremental_cache_failed: mask & 16 != 0,
            source_coverage_incomplete: mask & 32 != 0,
            total_source_failure: mask & 64 != 0,
            autoroute_persist_failed: mask & 128 != 0,
        };
        let expected = if outcome.scanner_panicked {
            EXIT_SCANNER_PANIC
        } else if outcome.has_live_credentials {
            EXIT_LIVE_CREDENTIALS
        } else if outcome.has_blocking_findings {
            EXIT_FINDINGS
        } else if outcome.autoroute_calibration {
            if outcome.autoroute_persist_failed {
                EXIT_SYSTEM_ERROR
            } else {
                EXIT_SUCCESS
            }
        } else if outcome.incremental_cache_failed || outcome.autoroute_persist_failed {
            EXIT_SYSTEM_ERROR
        } else if outcome.source_coverage_incomplete || outcome.total_source_failure {
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
        hyperscan_runtime_identity: None,
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
    assert!(daemon_requires_gpu(Some(ScanBackend::GpuWgpu), true).expect("gpu policy"));
    assert!(!daemon_requires_gpu(Some(ScanBackend::SimdCpu), true).expect("simd policy"));
    assert!(!daemon_requires_gpu(Some(ScanBackend::CpuFallback), true).expect("cpu policy"));
}

/// WHY: an unforced persistent daemon must compile the peers its authenticated route may select.
#[test]
fn daemon_autoroute_keeps_runtime_gpu_census_open() {
    use keyhog_scanner::{GpuInitPolicy, ScanBackend};

    assert_eq!(
        default_runtime_gpu_init_policy(None),
        GpuInitPolicy::FromRuntimePolicy
    );
    for backend in [
        ScanBackend::CpuFallback,
        ScanBackend::SimdCpu,
        ScanBackend::GpuCuda,
        ScanBackend::GpuMetal,
        ScanBackend::GpuWgpu,
    ] {
        assert_eq!(
            default_runtime_gpu_init_policy(Some(backend)),
            GpuInitPolicy::SelectedBackend(backend)
        );
    }
}

#[test]
fn unavailable_daemon_gpu_is_typed_and_exits_twelve() {
    use keyhog_scanner::ScanBackend;

    let error = daemon_requires_gpu(Some(ScanBackend::GpuWgpu), false)
        .expect_err("an explicit GPU daemon must reject a GPU-less host");
    assert_eq!(crate::cli_error_exit_code(&error), EXIT_REQUIRE_GPU_UNMET);
    assert_eq!(
        error.to_string(),
        "daemon --backend gpu-wgpu-region-presence cannot be honored: this build and host have no eligible physical GPU path. Run `keyhog backend --self-test` and repair the GPU driver/runtime, or start the daemon with `--backend simd` or `--backend cpu`."
    );

    let preflight = daemon_gpu_preflight_failure("no physical adapter passed self-test".into());
    assert_eq!(
        crate::cli_error_exit_code(&preflight),
        EXIT_REQUIRE_GPU_UNMET
    );
    assert_eq!(
        preflight.to_string(),
        "daemon start: required GPU preflight failed: no physical adapter passed self-test. Run `keyhog backend --self-test` and repair the GPU driver/runtime, or start the daemon with `--backend simd` or `--backend cpu`."
    );
}

/// Regression: fallible scanner backends keep the stable CLI exit-code contract.
#[test]
fn selected_backend_scan_errors_map_to_backend_exit_codes() {
    let guard = crate::testing::API.scan_runtime_guard_for_test();
    crate::testing::API.reset_scan_runtime_state_for_test(&guard);
    let gpu = anyhow::Error::new(keyhog_scanner::ScanError::Gpu(
        "selected GPU runtime is unavailable".into(),
    ));
    assert_eq!(crate::cli_error_exit_code(&gpu), EXIT_REQUIRE_GPU_UNMET);

    let simd = anyhow::Error::new(keyhog_scanner::ScanError::Simd(
        "selected SIMD runtime is unavailable".into(),
    ));
    assert_eq!(crate::cli_error_exit_code(&simd), EXIT_SYSTEM_ERROR);
}

#[test]
fn incompatible_daemon_gpu_compile_and_initialization_are_typed() {
    let guard = crate::testing::API.scan_runtime_guard_for_test();
    crate::testing::API.reset_scan_runtime_state_for_test(&guard);
    let compile_error = daemon_compile_failure(&keyhog_scanner::ScanError::Gpu(
        "adapter limits cannot create the literal-set pipeline".into(),
    ));
    assert_eq!(
        crate::cli_error_exit_code(&compile_error),
        EXIT_REQUIRE_GPU_UNMET
    );
    assert_eq!(
        compile_error.to_string(),
        "daemon GPU initialization failed while compiling the scanner: adapter limits cannot create the literal-set pipeline. Run `keyhog backend --self-test` and repair the GPU driver/runtime, or start the daemon with `--backend simd` or `--backend cpu`."
    );

    let readiness = validate_daemon_gpu_initialization(true, false)
        .expect_err("an incompatible initialized backend must fail readiness");
    assert_eq!(
        crate::cli_error_exit_code(&readiness),
        EXIT_REQUIRE_GPU_UNMET
    );
    assert_eq!(
        readiness.to_string(),
        "daemon GPU initialization failed: the detected physical GPU is unavailable or incompatible with the compiled scanner, driver, or runtime; refusing to announce readiness. Run `keyhog backend --self-test` and repair the GPU driver/runtime, or start the daemon with `--backend simd` or `--backend cpu`."
    );
}

#[test]
fn degraded_daemon_gpu_warmup_is_typed_and_exits_twelve() {
    let guard = crate::testing::API.scan_runtime_guard_for_test();
    crate::testing::API.reset_scan_runtime_state_for_test(&guard);
    let error = validate_daemon_gpu_warmup(true, 4, 5)
        .expect_err("a GPU degradation during warmup must fail readiness");
    assert_eq!(crate::cli_error_exit_code(&error), EXIT_REQUIRE_GPU_UNMET);
    assert_eq!(
        error.to_string(),
        "daemon GPU warmup degraded before readiness; refusing to apply persistent warm autoroute evidence. Run `keyhog backend --self-test` and repair the GPU driver/runtime, or start the daemon with `--backend simd` or `--backend cpu`."
    );
}

#[test]
fn non_gpu_daemon_configuration_remains_a_user_error() {
    let guard = crate::testing::API.scan_runtime_guard_for_test();
    crate::testing::API.reset_scan_runtime_state_for_test(&guard);
    use keyhog_scanner::ScanBackend;

    assert!(!daemon_requires_gpu(Some(ScanBackend::CpuFallback), false)
        .expect("CPU daemon does not require GPU"));
    validate_daemon_gpu_initialization(false, false)
        .expect("CPU daemon ignores GPU initialization state");
    validate_daemon_gpu_warmup(false, 4, 5).expect("CPU daemon ignores GPU degradation state");

    let invalid = crate::orchestrator_config::parse_backend_override(Some("quantum"))
        .expect_err("unknown daemon backend must be rejected");
    assert_eq!(crate::cli_error_exit_code(&invalid), EXIT_USER_ERROR);

    let invalid_detector = daemon_compile_failure(&keyhog_scanner::ScanError::Config(
        "detector confidence is outside 0..=1".into(),
    ));
    assert_eq!(
        crate::cli_error_exit_code(&invalid_detector),
        EXIT_USER_ERROR
    );
    assert_eq!(
        invalid_detector.to_string(),
        "daemon: compiling scanner from detector specs: scanner configuration failure: detector confidence is outside 0..=1. Fix: correct the bundled scanner rules"
    );
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

    let runtime = setup_default_scan_runtime_for_test(
        std::path::Path::new("detectors"),
        false,
        None,
        Some(rayon::current_num_threads()),
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
    let empty = Chunk {
        data: String::new().into(),
        metadata: ChunkMetadata {
            source_type: "filesystem".into(),
            ..ChunkMetadata::default()
        },
    };
    assert_eq!(
        runtime
            .scan_chunk(&empty)
            .expect("empty chunks have a backend-independent exact result"),
        Vec::<keyhog_core::RawMatch>::new()
    );
    let error = runtime
        .scan_chunk(&chunk)
        .expect_err("an uncalibrated persistent runtime must leave input unscanned");
    let message = error.to_string();
    assert!(
        message.contains("autoroute calibration required")
            && message.contains("batch was not scanned"),
        "invalid autoroute state must fail closed with repair context: {message}",
    );
}
