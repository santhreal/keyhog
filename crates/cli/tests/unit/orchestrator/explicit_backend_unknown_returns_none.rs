use crate::unit::orchestrator::support::ENV_LOCK;

#[test]
fn explicit_backend_unknown_env_is_rejected() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    unsafe {
        std::env::set_var("KEYHOG_BACKEND", "not-a-real-backend");
    }
    let error = keyhog::backend_env::validate_keyhog_backend_env()
        .expect_err("invalid KEYHOG_BACKEND must be rejected before routing");
    unsafe {
        std::env::remove_var("KEYHOG_BACKEND");
    }

    let message = error.to_string();
    assert!(
        message.contains("invalid KEYHOG_BACKEND value")
            && message.contains("not-a-real-backend")
            && message.contains("Fix: unset KEYHOG_BACKEND"),
        "diagnostic must name the bad value and the fix; got {message}"
    );
}
