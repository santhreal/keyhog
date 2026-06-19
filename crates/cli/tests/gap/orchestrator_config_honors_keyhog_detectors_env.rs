//! Contract gate: orchestrator_config does not read legacy KEYHOG_DETECTORS.

#[test]
fn orchestrator_config_ignores_legacy_keyhog_detectors_env() {
    let src = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/orchestrator_config.rs"
    ));
    assert!(
        !src.contains("KEYHOG_DETECTORS"),
        "orchestrator_config must use explicit --detectors/config paths, not KEYHOG_DETECTORS"
    );
}
