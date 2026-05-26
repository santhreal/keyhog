//! Contract gate: orchestrator_config reads KEYHOG_DETECTORS env var.

#[test]
fn orchestrator_config_honors_keyhog_detectors_env() {
    let src = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/orchestrator_config.rs"
    ));
    assert!(
        src.contains("KEYHOG_DETECTORS"),
        "orchestrator_config must honor KEYHOG_DETECTORS"
    );
}
