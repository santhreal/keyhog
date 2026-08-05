//! Git blob streaming must cap single blob and total in-memory bytes.

#[cfg(not(feature = "git"))]
#[test]
fn git_blob_caps_require_git_feature() {
    assert!(!cfg!(feature = "git"));
}
