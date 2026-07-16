//! Migrated from `src/rule_filter.rs` inline tests.
#[test]
fn unknown_severity_is_rejected() {
    let toml = r#"
[[suppress]]
detector = "x"
severity = "panic"
ml = { match_mode = "disabled", entropy_mode = "disabled", weight = 0.0, context_radius_lines = 0 }
"#;
    let err = keyhog_core::testing::CoreTestApi::rule_suppressor_parse(
        &keyhog_core::testing::TestApi,
        toml,
    )
    .expect_err("must reject");
    let msg = format!("{err}");
    assert!(msg.contains("severity"), "got: {msg}");
}
