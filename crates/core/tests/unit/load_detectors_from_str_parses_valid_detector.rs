//! Migrated from `src/spec/load.rs` inline tests.
use keyhog_core::Severity;
fn valid_toml() -> &'static str {
    r#"
        [detector]
        id = "demo"
        name = "Demo"
        service = "demo"
        severity = "high"
        ml = { match_mode = "disabled", entropy_mode = "disabled", weight = 0.0, context_radius_lines = 0 }
        keywords = ["demo"]

        [[detector.patterns]]
        regex = "demo_[A-Z0-9]{8}"
    "#
}
#[test]
fn load_detectors_from_str_parses_valid_detector() {
    let specs = keyhog_core::testing::CoreTestApi::load_detectors_from_str(
        &keyhog_core::testing::TestApi,
        valid_toml(),
    )
    .unwrap();
    assert_eq!(specs.len(), 1);
    assert_eq!(specs[0].id, "demo");
    assert_eq!(specs[0].severity, Severity::High);
}
