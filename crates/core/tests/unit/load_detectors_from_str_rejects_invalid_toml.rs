//! Migrated from `src/spec/load.rs` inline tests.
use keyhog_core::{load_detectors_from_str, load_detectors_with_gate, Severity, SpecError};
fn valid_toml() -> &'static str {
    r#"
        [detector]
        id = "demo"
        name = "Demo"
        service = "demo"
        severity = "high"
        keywords = ["demo"]

        [[detector.patterns]]
        regex = "demo_[A-Z0-9]{8}"
    "#
}
#[test]
fn load_detectors_from_str_rejects_invalid_toml() {
    let err = load_detectors_from_str("not valid toml [[[[").unwrap_err();
    assert!(matches!(err, SpecError::InvalidToml { .. }));
}
