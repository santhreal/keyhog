//! Inline metadata `reason=` must survive Allowlist::parse.

#[test]
fn allowlist_inline_metadata_reason_parsed() {
    let raw = r#"detector:foo ; reason="rotate after release" ; expires=2099-01-01 ; approved_by="alice@example.com""#;
    let al =
        keyhog_core::testing::CoreTestApi::allowlist_parse(&keyhog_core::testing::TestApi, raw);
    assert!(al.ignored_detectors.contains("foo"));
}

#[test]
fn allowlist_quoted_semicolon_metadata_does_not_create_fake_expires() {
    let raw = r#"detector:foo ; expires=2099-01-01 ; reason="approved; expires=1970-01-01""#;
    let al =
        keyhog_core::testing::CoreTestApi::allowlist_parse(&keyhog_core::testing::TestApi, raw);
    assert!(
        al.ignored_detectors.contains("foo"),
        "semicolons inside quoted metadata values must not be parsed as new fields"
    );
}
