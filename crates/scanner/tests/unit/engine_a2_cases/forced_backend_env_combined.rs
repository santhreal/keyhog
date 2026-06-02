use keyhog_scanner::hw_probe::{parse_backend_str, ScanBackend};

#[test]
fn test_forced_backend_env_all_scenarios() {
    // Pure string→backend mapping for every recognized scenario. Asserting on
    // `parse_backend_str` instead of mutating the process-global `KEYHOG_BACKEND`
    // keeps this off the env-race that lets a forced-but-unavailable GPU value
    // reach a concurrent scan and abort the whole harness via gpu_forced's
    // process-exit (see parse_backend_str docs).

    // Unset / unrecognized → no forced backend.
    assert!(parse_backend_str("").is_none());
    assert!(parse_backend_str("garbage-value").is_none());

    // Forced GPU.
    assert_eq!(parse_backend_str("gpu"), Some(ScanBackend::Gpu));

    // Forced MegaScan.
    assert_eq!(parse_backend_str("mega-scan"), Some(ScanBackend::MegaScan));
}
