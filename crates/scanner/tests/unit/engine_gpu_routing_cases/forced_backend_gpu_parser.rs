use keyhog_scanner::hw_probe::testing::{parse_backend_str, ScanBackend};

#[test]
fn forced_backend_gpu_parser() {
    // Pure string→backend mapping assertion. This must NOT mutate the global
    // test backend override: a forced GPU value races with every concurrent
    // scan in the parallel `all_tests` pool, and gpu_forced reacts to a
    // forced-but-unavailable GPU by exiting the whole process (harness abort).
    // `parse_backend_str` is the single source of truth for backend strings.
    assert_eq!(parse_backend_str("gpu"), None);
    assert_eq!(
        parse_backend_str("gpu-cuda-region-presence"),
        Some(ScanBackend::GpuCuda)
    );
    assert_eq!(
        parse_backend_str("gpu-wgpu-region-presence"),
        Some(ScanBackend::GpuWgpu)
    );
    // SIMD/CPU arms and the case-insensitive contract.
    assert_eq!(parse_backend_str("simd"), Some(ScanBackend::SimdCpu));
    assert_eq!(parse_backend_str("simd-regex"), Some(ScanBackend::SimdCpu));
    assert_eq!(parse_backend_str("cpu"), Some(ScanBackend::CpuFallback));
    assert_eq!(
        parse_backend_str("cpu-fallback"),
        Some(ScanBackend::CpuFallback)
    );
    for retired in [
        "gpu-zero-copy",
        "literal-set",
        "mega-scan",
        "megascan",
        "gpu-mega-scan",
        "regex-nfa",
        "rule-pipeline",
        "hyperscan",
        "scalar",
    ] {
        assert_eq!(parse_backend_str(retired), None);
    }

    // Unknown strings (and `auto`, which means "defer to the router") are not
    // backends this parser names.
    assert_eq!(parse_backend_str("auto"), None);
    assert_eq!(parse_backend_str("garbage-value"), None);
}
