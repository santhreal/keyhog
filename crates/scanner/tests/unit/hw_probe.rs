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
    let banner = startup_banner(&hw, 896, 1509);
    assert!(banner.contains("AVX2"));
    assert!(banner.contains("Hyperscan"));
    assert!(banner.contains("io_uring"));
    assert!(banner.contains("896 detectors"));
}

#[test]
fn windows_powershell_fallback() {
    // Just verify the function compiles and doesn't panic
    #[cfg(target_os = "windows")]
    {
        let _ = windows_physical_cores();
    }
}
