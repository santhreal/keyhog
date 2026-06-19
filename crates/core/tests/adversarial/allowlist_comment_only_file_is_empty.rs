//! Adversarial: comment-only allowlist content yields empty suppressions.

#[test]
fn allowlist_comment_only_file_is_empty() {
    let al = keyhog_core::testing::CoreTestApi::allowlist_parse(
        &keyhog_core::testing::TestApi,
        "# just a comment
# another
",
    );
    assert!(al.ignored_detectors.is_empty());
    assert!(al.ignored_paths.is_empty());
    assert!(al.credential_hashes.is_empty());
}
