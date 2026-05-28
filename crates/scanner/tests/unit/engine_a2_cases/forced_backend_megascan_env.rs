use keyhog_scanner::hw_probe::{clear_test_backend_override, forced_backend_from_env, ScanBackend};
#[test]
fn forced_backend_megascan_env() {
    clear_test_backend_override();
    unsafe {
        std::env::set_var("KEYHOG_BACKEND", "mega-scan");
    }
    assert_eq!(forced_backend_from_env(), Some(ScanBackend::MegaScan));
    unsafe {
        std::env::remove_var("KEYHOG_BACKEND");
    }
}
