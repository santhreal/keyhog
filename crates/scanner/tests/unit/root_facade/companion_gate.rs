//! Companion-gate unit coverage (migrated out of src inline tests).

#[test]
fn formbuilder_requires_form_or_fused_token() {
    let src = r#"(?:123[_\-\s]*form[_\-\s]*builder|123FORMBUILDER)[_.\s]*(?:api[_\-\s]*key)"#;
    let arms = keyhog_scanner::testing::companion_arms_for_test(src);
    assert!(!arms.is_empty(), "expected companion arms for 123formbuilder");
    let padding = "const ordinary_value = 1234567890;\n";
    assert!(!keyhog_scanner::testing::companions_allow_for_test(src, padding));
    assert!(keyhog_scanner::testing::companions_allow_for_test(
        src,
        "123_form_builder_api_key=abcdef"
    ));
    assert!(keyhog_scanner::testing::companions_allow_for_test(
        src,
        "123FORMBUILDER_api_key=abcdef"
    ));
}

#[test]
fn ip_api_requires_api_companion() {
    let src = r#"(?:IP[_\-\s]*API|ip[_\-\s]*api)(?:_KEY)?[=:\s"']+([a-zA-Z0-9_-]{10,})"#;
    let lorem = "lorem ipsum dolor sit amet, consectetur adipiscing elit.\n";
    assert!(!keyhog_scanner::testing::companions_allow_for_test(src, lorem));
    assert!(keyhog_scanner::testing::companions_allow_for_test(
        src,
        "IPAPI_KEY=WnGcEBigw6"
    ));
}
