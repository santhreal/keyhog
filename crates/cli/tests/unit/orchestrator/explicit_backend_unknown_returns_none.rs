use keyhog::orchestrator::explicit_backend_override;

#[test]
fn explicit_backend_unknown_returns_none() {
    std::env::set_var("KEYHOG_BACKEND", "not-a-real-backend");
    assert!(explicit_backend_override().is_none());
    std::env::remove_var("KEYHOG_BACKEND");
}
