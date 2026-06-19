//! Migrated from `src/spec/load.rs` inline tests.
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
    let specs = keyhog_core::testing::CoreTestApi::load_detectors_from_str(
        &keyhog_core::testing::TestApi,
        toml,
    )
    .unwrap();
    assert!(specs[0].keywords.is_empty());
    assert_eq!(specs[0].patterns[0].regex, "x{4}");
}
