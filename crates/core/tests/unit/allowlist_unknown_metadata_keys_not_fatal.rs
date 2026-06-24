//! Parse-only tests keep recovering the suppression entry; operator file loads
//! reject unknown metadata keys in the governance regression suite.

#[test]
fn allowlist_parse_preserves_entry_when_unknown_metadata_key_is_present() {
    let al = keyhog_core::testing::CoreTestApi::allowlist_parse(
        &keyhog_core::testing::TestApi,
        "detector:bar ; foo=bar; reason=ok ; expires=2099-12-31",
    );
    assert!(al.ignored_detectors.contains("bar"));
}
