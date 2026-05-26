//! Contract gate: orchestrator_config reads KEYHOG_THREADS env var.

#[test]
fn orchestrator_config_honors_keyhog_threads_env() {
    let src = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/orchestrator_config.rs"));
    assert!(src.contains("KEYHOG_THREADS"), "orchestrator_config must honor KEYHOG_THREADS");
}
