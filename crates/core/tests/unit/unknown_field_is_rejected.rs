//! Migrated from `src/rule_filter.rs` inline tests.
#[test]
fn unknown_field_is_rejected() {
    let toml = r#"
[[suppress]]
not_a_field = "x"
"#;
    let err = keyhog_core::testing::CoreTestApi::rule_suppressor_parse(
        &keyhog_core::testing::TestApi,
        toml,
    )
    .expect_err("must reject");
    let msg = format!("{err}");
    // serde's deny_unknown_fields produces a message naming the
    // bad field; just verify it errors.
    assert!(
        msg.contains("not_a_field") || msg.contains("unknown"),
        "got: {msg}"
    );
}
