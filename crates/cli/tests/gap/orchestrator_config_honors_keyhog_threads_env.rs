//! Contract gate: orchestrator_config must not read KEYHOG_THREADS env var.

#[test]
fn orchestrator_config_ignores_keyhog_threads_env() {
    let src = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/orchestrator_config.rs"
    ));
    assert!(
        !src.contains("KEYHOG_THREADS"),
        "thread count must come from --threads / [scan].threads, not ambient KEYHOG_THREADS"
    );
}
