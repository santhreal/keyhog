use keyhog_scanner::hw_probe::testing::{parse_backend_str, ScanBackend};

#[test]
fn forced_backend_parser_covers_all_scenarios() {
    // Pure string→backend mapping for every recognized scenario. Asserting on
    // `parse_backend_str` instead of mutating the process-global `KEYHOG_BACKEND`
    // keeps this off the legacy-env race that lets a forced-but-unavailable GPU value
    // reach a concurrent scan and abort the whole harness via gpu_forced's
    // process-exit (see parse_backend_str docs).

    // Unset / unrecognized → no forced backend.
    assert!(parse_backend_str("").is_none());
    assert!(parse_backend_str("garbage-value").is_none());

    // Forced GPU peers are explicit. The ambiguous generic token is rejected.
    assert_eq!(parse_backend_str("gpu"), None);
    assert_eq!(parse_backend_str("gpu-cuda"), Some(ScanBackend::GpuCuda));
    assert_eq!(parse_backend_str("gpu-wgpu"), Some(ScanBackend::GpuWgpu));

    // Retired MegaScan strings are not forced backends.
    assert_eq!(parse_backend_str("mega-scan"), None);
}
