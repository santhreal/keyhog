//! Migrated from `src/spec/load.rs` inline tests.
use keyhog_core::{load_detectors_from_str, load_detectors_with_gate, SpecError, Severity};
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
    fn load_detectors_from_str_parses_valid_detector() {
        let specs = load_detectors_from_str(valid_toml()).unwrap();
        assert_eq!(specs.len(), 1);
        assert_eq!(specs[0].id, "demo");
        assert_eq!(specs[0].severity, Severity::High);
    }
