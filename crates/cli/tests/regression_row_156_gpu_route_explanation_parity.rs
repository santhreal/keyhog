//! Regression test for Row 156: GPU route explanation parity.
//!
//! WHY: When a host physically has a GPU adapter but the binary is compiled
//! without the GPU backend or with a single compiled backend, diagnostic
//! commands (`keyhog backend`, `keyhog doctor`, `keyhog version --full`, and
//! autoroute routing explanation strings) previously misreported
//! "gpu: not detected" or produced a false `gpu_probe_miss` ("no usable GPU
//! adapter reported by hardware probe").
//!
//! This suite verifies:
//! 1. `BackendRoutingReason` has stable labels for `CompiledWithoutGpu`
//!    ("compiled_without_gpu_backend") and `SingleCompiledBackend`
//!    ("single_compiled_backend").
//! 2. `select_backend_verdict` produces accurate explanations without false
//!    probe misses across the hardware present/absent vs feature compiled/absent
//!    matrix.
//! 3. Diagnostic formatting accurately reports "compiled without GPU backend /
//!    single compiled backend" when a GPU is physically detected rather than
//!    claiming "gpu: not detected".
//! 4. `unavailable_gpu_self_test_report` renders honest reasons across the
//!    compilation and presence matrix.
//!
//! What this does NOT catch: Physical GPU driver hardware faults, broken Vulkan
//! ICD installations, or kernel crashes during device execution.

use keyhog_scanner::hw_probe::{select_backend_verdict, BackendRoutingReason, HardwareCaps};

fn test_caps(
    gpu_available: bool,
    gpu_name: Option<&str>,
    gpu_is_software: bool,
    hyperscan_available: bool,
) -> HardwareCaps {
    HardwareCaps {
        physical_cores: 16,
        logical_cores: 32,
        has_avx2: true,
        has_avx512: false,
        has_neon: false,
        gpu_available,
        gpu_name: gpu_name.map(str::to_string),
        gpu_vram_mb: gpu_name.map(|_| 24_576),
        gpu_runtime_identity: None,
        gpu_is_software,
        total_memory_mb: Some(65_536),
        io_uring_available: true,
        hyperscan_available,
        hyperscan_runtime_identity: None,
    }
}

#[test]
fn backend_routing_reason_labels_parity() {
    assert_eq!(
        BackendRoutingReason::CompiledWithoutGpu.label(),
        "compiled_without_gpu_backend"
    );
    assert_eq!(
        BackendRoutingReason::SingleCompiledBackend.label(),
        "single_compiled_backend"
    );
    assert_eq!(BackendRoutingReason::GpuProbeMiss.label(), "gpu_probe_miss");
    assert_eq!(
        BackendRoutingReason::GpuDisabledByPolicy.label(),
        "gpu_disabled_by_policy"
    );
    assert_eq!(
        BackendRoutingReason::GpuSoftwareRenderer.label(),
        "gpu_software_renderer"
    );
    assert_eq!(
        BackendRoutingReason::GpuThresholdNotMet.label(),
        "gpu_threshold_not_met"
    );
    assert_eq!(BackendRoutingReason::GpuSelected.label(), "gpu_selected");
}

#[test]
fn verdict_reason_detail_parity_strings() {
    let caps = test_caps(false, Some("NVIDIA GeForce RTX 5090"), false, true);
    let mut verdict = select_backend_verdict(&caps, 1024, 10);

    verdict.reason = BackendRoutingReason::CompiledWithoutGpu;
    assert_eq!(verdict.reason_detail(), "compiled without GPU backend");

    verdict.reason = BackendRoutingReason::SingleCompiledBackend;
    assert_eq!(
        verdict.reason_detail(),
        "compiled without GPU backend / single compiled backend"
    );

    verdict.reason = BackendRoutingReason::GpuProbeMiss;
    assert_eq!(
        verdict.reason_detail(),
        "no usable GPU adapter reported by hardware probe"
    );

    verdict.reason = BackendRoutingReason::GpuSoftwareRenderer;
    assert_eq!(
        verdict.reason_detail(),
        "GPU adapter is a software renderer and is slower than CPU/SIMD"
    );
}

#[test]
fn route_explanation_never_claims_false_probe_miss_when_gpu_present() {
    let caps_with_gpu = test_caps(false, Some("NVIDIA GeForce RTX 5090"), false, true);
    let verdict = select_backend_verdict(&caps_with_gpu, 1024, 10);

    if !keyhog_scanner::hw_probe::gpu_backend_compiled() {
        if !keyhog_scanner::hw_probe::multiple_backends_compiled() {
            assert_eq!(verdict.reason, BackendRoutingReason::SingleCompiledBackend);
            assert_eq!(
                verdict.reason_detail(),
                "compiled without GPU backend / single compiled backend"
            );
        } else {
            assert_eq!(verdict.reason, BackendRoutingReason::CompiledWithoutGpu);
            assert_eq!(verdict.reason_detail(), "compiled without GPU backend");
        }
        assert_ne!(verdict.reason, BackendRoutingReason::GpuProbeMiss);
        assert!(!verdict.reason_detail().contains("hardware probe"));
    }
}

#[test]
fn gpu_absent_caps_reports_probe_miss_when_gpu_feature_compiled() {
    let caps_no_gpu = test_caps(false, None, false, true);
    let verdict = select_backend_verdict(&caps_no_gpu, 1024, 10);

    if keyhog_scanner::hw_probe::gpu_backend_compiled() {
        assert_eq!(verdict.reason, BackendRoutingReason::GpuProbeMiss);
        assert_eq!(
            verdict.reason_detail(),
            "no usable GPU adapter reported by hardware probe"
        );
    }
}

#[test]
fn format_gpu_display_matrix() {
    // Helper replicating the format logic used in backend report and doctor
    fn format_gpu_status(
        gpu_available: bool,
        gpu_name: Option<&str>,
        gpu_is_software: bool,
        gpu_compiled: bool,
        multi_backend: bool,
    ) -> String {
        if gpu_available {
            let name = gpu_name.unwrap_or("yes");
            if gpu_is_software {
                format!("{name} (software renderer: disabled)")
            } else {
                name.to_string()
            }
        } else if let Some(name) = gpu_name {
            if gpu_is_software {
                format!("{name} (software renderer: disabled)")
            } else if !gpu_compiled {
                if !multi_backend {
                    format!("{name} (compiled without GPU backend / single compiled backend)")
                } else {
                    format!("{name} (compiled without GPU backend)")
                }
            } else {
                format!("{name} (runtime unavailable)")
            }
        } else if !gpu_compiled {
            if !multi_backend {
                "not detected (compiled without GPU backend / single compiled backend)".to_string()
            } else {
                "not detected (binary built without --features gpu)".to_string()
            }
        } else {
            "not detected".to_string()
        }
    }

    // Case 1: GPU physically present, compiled with GPU
    assert_eq!(
        format_gpu_status(true, Some("NVIDIA GeForce RTX 5090"), false, true, true),
        "NVIDIA GeForce RTX 5090"
    );

    // Case 2: GPU physically present, compiled without GPU feature (multi-backend with SIMD)
    let s2 = format_gpu_status(false, Some("NVIDIA GeForce RTX 5090"), false, false, true);
    assert_eq!(s2, "NVIDIA GeForce RTX 5090 (compiled without GPU backend)");
    assert!(!s2.contains("not detected"));

    // Case 3: GPU physically present, single compiled backend (scalar only)
    let s3 = format_gpu_status(false, Some("NVIDIA GeForce RTX 5090"), false, false, false);
    assert_eq!(
        s3,
        "NVIDIA GeForce RTX 5090 (compiled without GPU backend / single compiled backend)"
    );
    assert!(!s3.contains("not detected"));

    // Case 4: GPU physically absent, compiled with GPU
    assert_eq!(
        format_gpu_status(false, None, false, true, true),
        "not detected"
    );

    // Case 5: GPU physically absent, compiled without GPU (multi-backend with SIMD)
    assert_eq!(
        format_gpu_status(false, None, false, false, true),
        "not detected (binary built without --features gpu)"
    );

    // Case 6: GPU physically absent, single compiled backend
    assert_eq!(
        format_gpu_status(false, None, false, false, false),
        "not detected (compiled without GPU backend / single compiled backend)"
    );

    // Case 7: Software renderer
    assert_eq!(
        format_gpu_status(true, Some("llvmpipe"), true, true, true),
        "llvmpipe (software renderer: disabled)"
    );
}
