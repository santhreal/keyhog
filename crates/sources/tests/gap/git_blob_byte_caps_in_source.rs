//! Git blob streaming must cap single blob and total in-memory bytes.

#[cfg(feature = "git")]
#[test]
fn git_blob_byte_caps_in_source() {
    let src = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/git/source.rs"))
        .expect("git/source.rs");
    assert!(
        !src.contains("MAX_GIT_BLOB_BYTES")
            && !src.contains("MAX_GIT_TOTAL_BYTES")
            && !src.contains("MAX_GIT_CHUNKS"),
        "Git source caps must be owned by SourceLimits"
    );
    assert!(
        src.contains("git_blob_bytes")
            && src.contains("git_total_bytes")
            && src.contains("git_chunk_count"),
        "Git blob source must use resolved SourceLimits"
    );
}

#[cfg(not(feature = "git"))]
#[test]
fn git_blob_caps_require_git_feature() {
    assert!(!cfg!(feature = "git"));
}
