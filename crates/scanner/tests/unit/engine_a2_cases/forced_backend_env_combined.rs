use keyhog_scanner::hw_probe::{clear_test_backend_override, forced_backend_from_env, ScanBackend};

#[test]
fn test_forced_backend_env_all_scenarios() {
    // 1. Scenario: unset is None
    unsafe {
        std::env::remove_var("KEYHOG_BACKEND");
    }
    assert!(forced_backend_from_env().is_none());

    // 2. Scenario: forced GPU
    unsafe {
        std::env::set_var("KEYHOG_BACKEND", "gpu");
    }
    assert_eq!(forced_backend_from_env(), Some(ScanBackend::Gpu));

    // 3. Scenario: forced MegaScan
    clear_test_backend_override();
    unsafe {
        std::env::set_var("KEYHOG_BACKEND", "mega-scan");
    }
    assert_eq!(forced_backend_from_env(), Some(ScanBackend::MegaScan));

    // Cleanup
    unsafe {
        std::env::remove_var("KEYHOG_BACKEND");
    }
}
