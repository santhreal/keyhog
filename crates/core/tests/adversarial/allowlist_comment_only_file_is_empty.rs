//! Adversarial: comment-only allowlist content yields empty suppressions.

use keyhog_core::Allowlist;

#[test]
fn allowlist_comment_only_file_is_empty() {
    let al = Allowlist::parse(
        "# just a comment
# another
",
    );
    assert!(al.ignored_detectors.is_empty());
    assert!(al.ignored_paths.is_empty());
    assert!(al.credential_hashes.is_empty());
}
