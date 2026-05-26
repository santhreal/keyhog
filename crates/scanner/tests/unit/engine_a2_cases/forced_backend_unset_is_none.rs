use keyhog_scanner::hw_probe::forced_backend_from_env;
#[test]
fn forced_backend_unset_is_none() {
    unsafe {
        std::env::remove_var("KEYHOG_BACKEND");
    }
    assert!(forced_backend_from_env().is_none());
}
