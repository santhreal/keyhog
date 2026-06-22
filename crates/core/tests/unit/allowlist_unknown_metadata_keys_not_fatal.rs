//! Unknown metadata keys must not prevent parsing known fields.

#[test]
fn allowlist_unknown_metadata_keys_not_fatal() {
    let al = keyhog_core::testing::CoreTestApi::allowlist_parse(
        &keyhog_core::testing::TestApi,
        "detector:bar ; foo=bar; reason=ok ; expires=2099-12-31",
    );
    assert!(al.ignored_detectors.contains("bar"));
}
