//! Git blob streaming must cap single blob and total in-memory bytes.

#[cfg(feature = "git")]
#[test]
fn git_blob_byte_caps_in_source() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/git");
    assert!(
        std::fs::read_to_string(root.join("mod.rs"))
            .expect("git/mod.rs")
            .contains("fn git_blob_bytes_limit_usize("),
        "git module must own the git_blob_bytes usize conversion for source buffers"
    );

    let source = std::fs::read_to_string(root.join("source.rs")).expect("git/source.rs");
    assert!(
        !source.contains("MAX_GIT_BLOB_BYTES")
            && !source.contains("MAX_GIT_TOTAL_BYTES")
            && !source.contains("MAX_GIT_CHUNKS"),
        "Git source caps must be owned by SourceLimits"
    );
    assert!(
        source.contains("git_blob_bytes")
            && source.contains("git_total_bytes")
            && source.contains("git_chunk_count"),
        "Git blob source must use resolved SourceLimits"
    );

    for rel in ["diff.rs", "history.rs"] {
        let src = std::fs::read_to_string(root.join(rel)).expect("git hunk source readable");
        assert!(
            !src.contains("10 * 1024 * 1024"),
            "{rel} must not hardcode the git hunk buffer cap; use SourceLimits::git_blob_bytes"
        );
        assert!(
            src.contains("git_blob_bytes_limit_usize(limits)") && src.contains("hunk_byte_cap"),
            "{rel} must use the shared git_blob_bytes hunk cap"
        );
    }
}

#[cfg(not(feature = "git"))]
#[test]
fn git_blob_caps_require_git_feature() {
    assert!(!cfg!(feature = "git"));
}
