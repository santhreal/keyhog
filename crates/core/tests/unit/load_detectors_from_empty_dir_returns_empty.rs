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
fn load_detectors_from_empty_dir_returns_empty() {
    let dir = tempfile::tempdir().unwrap();
    let specs = load_detectors_with_gate(dir.path(), true).unwrap();
    assert!(specs.is_empty());
}
