use keyhog_scanner::hw_probe::{forced_backend_from_env, ScanBackend};
#[test]
fn forced_backend_megascan_env() {
    unsafe { std::env::set_var("KEYHOG_BACKEND", "mega-scan"); }
    assert_eq!(forced_backend_from_env(), Some(ScanBackend::MegaScan));
    unsafe { std::env::remove_var("KEYHOG_BACKEND"); }
}
