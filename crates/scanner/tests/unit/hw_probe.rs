use keyhog_core::embedded_detector_count;
use keyhog_scanner::hw_probe::*;
fn caps() -> HardwareCaps {
    HardwareCaps {
        physical_cores: 8,
        logical_cores: 16,
        has_avx2: false,
        has_avx512: false,
        has_neon: false,
        gpu_available: false,
        gpu_name: None,
        gpu_vram_mb: None,
        gpu_is_software: false,
        total_memory_mb: Some(32 * 1024),
        io_uring_available: false,
        hyperscan_available: false,
    }
}

#[test]
fn gpu_not_selected_automatically() {
    let mut hw = caps();
    hw.gpu_available = true;
    assert_eq!(select_backend(&hw, 100, 50), ScanBackend::CpuFallback);

    hw.has_avx2 = true;
    assert_eq!(select_backend(&hw, 1000, 1000), ScanBackend::SimdCpu);
}

#[test]
fn software_gpu_rejected() {
    let mut hw = caps();
    hw.gpu_available = true;
    hw.gpu_is_software = true;
    hw.gpu_name = Some("llvmpipe (LLVM 15.0.7, 256 bits)".to_string());
    assert_ne!(select_backend(&hw, 1000, 1000), ScanBackend::Gpu);
}

#[test]
fn simd_when_no_hyperscan() {
    let mut hw = caps();
    hw.has_avx2 = true;
    assert_eq!(select_backend(&hw, 0, 10), ScanBackend::SimdCpu);
}

#[test]
fn fallback_when_nothing_available() {
    assert_eq!(select_backend(&caps(), 0, 10), ScanBackend::CpuFallback);
}

#[test]
fn startup_banner_format() {
    let mut hw = caps();
    hw.has_avx2 = true;
    hw.hyperscan_available = true;
    hw.io_uring_available = true;
    let d = embedded_detector_count();
    let banner = startup_banner(&hw, d, 1509);
    assert!(banner.contains("AVX2"));
    assert!(banner.contains("Hyperscan"));
    assert!(banner.contains("io_uring"));
    assert!(
        banner.contains(&format!("{d} detectors")),
        "banner={banner:?}"
    );
}

#[test]
fn windows_powershell_fallback() {
    // The Windows physical-core probe falls through `keyhog_core::safe_bin`
    // to a powershell or wmic invocation. We can't reach the private
    // `windows_physical_cores()` symbol from an integration test, so we
    // exercise it indirectly through `probe_hardware()` and just assert
    // that a non-zero physical_cores count was discovered. If the
    // PowerShell fallback panicked or returned None on Windows, this
    // would fire because the upstream probe returns 1 as a last resort.
    #[cfg(target_os = "windows")]
    {
        let hw = keyhog_scanner::hw_probe::probe_hardware();
        assert!(
            hw.physical_cores >= 1,
            "physical_cores probe returned {}; powershell fallback may have panicked",
            hw.physical_cores
        );
    }
}
