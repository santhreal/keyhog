use keyhog_core::embedded_detector_count;
use keyhog_scanner::hw_probe::testing::*;
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
        gpu_runtime_identity: None,
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
fn hardware_probes_do_not_fall_back_to_path_binaries() {
    let src = include_str!("../../src/hw_probe/platform.rs");
    assert!(
        !src.contains("resolve_or_fallback"),
        "hardware probes must not execute PATH binaries when trusted resolution misses"
    );
    assert!(
        src.contains("keyhog_core::resolve_safe_bin(bin_name)")
            && src.contains("run_probe_command(")
            && src.contains(r#""sysctl""#)
            && src.contains(r#""powershell""#)
            && src.contains(r#""wmic""#),
        "hardware probes must route platform command names through the trusted absolute binary resolver helper"
    );
    assert!(
        src.contains("fn run_probe_command("),
        "platform probe command spawning must have one helper owner"
    );
    assert_eq!(
        src.matches("std::process::Command::new").count(),
        1,
        "platform probes must not duplicate Command::new boilerplate outside run_probe_command"
    );
}

#[test]
fn gpu_tier_classifier_uses_series_prefixes_for_rtx_40_50_cards() {
    let src = include_str!("../../src/hw_probe/tier.rs");
    assert!(src.contains(r#"lower.contains("rtx 40")"#));
    assert!(src.contains(r#"lower.contains("rtx 50")"#));
    for redundant in [
        "rtx 4090", "rtx 4080", "rtx 4070", "rtx 5090", "rtx 5080", "rtx 5070",
    ] {
        assert!(
            !src.contains(redundant),
            "RTX 40/50 submodel {redundant} is already covered by the series prefix"
        );
    }
}

#[cfg(target_os = "linux")]
#[test]
fn linux_cpuinfo_parser_skips_malformed_records() {
    let cpuinfo = "\
physical id\t: 0
core id\t\t: 0

physical id without separator
core id\t\t: 1

physical id\t: 1
core id\t\t: 0
";

    assert_eq!(
        linux_physical_cores_from_cpuinfo(cpuinfo),
        Some(2),
        "one malformed cpuinfo record must not abort counting later valid core pairs"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn linux_meminfo_parser_skips_malformed_memtotal_lines() {
    let meminfo = "\
MemTotal:
MemFree:        1024 kB
MemTotal:    1048576 kB
";

    assert_eq!(
        linux_total_memory_mb_from_meminfo(meminfo),
        Some(1024),
        "a malformed MemTotal line must not abort before a later valid line"
    );
}

#[test]
fn windows_powershell_probe_still_reports_cores() {
    // We can't reach the private `windows_physical_cores()` symbol from an
    // integration test, so exercise it indirectly through `probe_hardware()`.
    // If trusted PowerShell/WMIC probing regresses on Windows, the upstream
    // probe still returns a conservative >=1 core count rather than panicking.
    #[cfg(target_os = "windows")]
    {
        let hw = keyhog_scanner::hw_probe::testing::probe_hardware();
        assert!(
            hw.physical_cores >= 1,
            "physical_cores probe returned {}; trusted PowerShell/WMIC probe may have panicked",
            hw.physical_cores
        );
    }
}
