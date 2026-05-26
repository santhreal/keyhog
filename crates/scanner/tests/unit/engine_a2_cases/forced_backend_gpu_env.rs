use keyhog_scanner::hw_probe::{forced_backend_from_env, ScanBackend};
#[test]
fn forced_backend_gpu_env() {
    unsafe { std::env::set_var("KEYHOG_BACKEND", "gpu"); }
    assert_eq!(forced_backend_from_env(), Some(ScanBackend::Gpu));
    unsafe { std::env::remove_var("KEYHOG_BACKEND"); }
}
