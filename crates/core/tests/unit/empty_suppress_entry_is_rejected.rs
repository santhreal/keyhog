//! Migrated from `src/rule_filter.rs` inline tests.
#[test]
fn empty_suppress_entry_is_rejected() {
    let toml = r#"
[[suppress]]
"#;
    let err = keyhog_core::testing::CoreTestApi::rule_suppressor_parse(
        &keyhog_core::testing::TestApi,
        toml,
    )
    .expect_err("must reject");
    let msg = format!("{err}");
    assert!(msg.contains("no conditions"), "got: {msg}");
}
