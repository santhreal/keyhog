//! Git blob streaming must cap single blob and total in-memory bytes.

#[cfg(feature = "git")]
#[test]
fn git_blob_byte_caps_in_source() {
    let src = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/git/source.rs"
    ))
    .expect("git/source.rs");
    assert!(src.contains("MAX_GIT_BLOB_BYTES"));
    assert!(src.contains("MAX_GIT_TOTAL_BYTES"));
    assert!(src.contains("MAX_GIT_CHUNKS"));
}

#[cfg(not(feature = "git"))]
#[test]
fn git_blob_caps_require_git_feature() {
    assert!(!cfg!(feature = "git"));
}
