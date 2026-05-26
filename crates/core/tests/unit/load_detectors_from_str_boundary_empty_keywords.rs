//! Migrated from `src/spec/load.rs` inline tests.
use keyhog_core::spec::{load_detectors_from_str, load_detectors_with_gate, SpecError, Severity};
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
    fn load_detectors_from_str_boundary_empty_keywords() {
        let toml = r#"
        [detector]
        id = "bare"
        name = "Bare"
        service = "bare"
        severity = "info"
        keywords = []

        [[detector.patterns]]
        regex = "x{4}"
        "#;
        let specs = load_detectors_from_str(toml).unwrap();
        assert!(specs[0].keywords.is_empty());
        assert_eq!(specs[0].patterns[0].regex, "x{4}");
    }
