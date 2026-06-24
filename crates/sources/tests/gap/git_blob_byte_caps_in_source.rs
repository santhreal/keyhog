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
        source.contains("limits.git_blob_bytes")
            && source.contains("limits.git_chunk_count")
            && source.contains("git_history_cap_status(total_bytes, chunk_count, limits)")
            && source.contains("git_history_cap_status(*total_bytes, *chunk_count, self.limits)"),
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
        assert!(
            src.contains("git_history_cap_status(total_bytes, chunk_count, limits)"),
            "{rel} must enforce SourceLimits::git_total_bytes and SourceLimits::git_chunk_count before continuing history/diff enumeration"
        );
    }

    let diff = std::fs::read_to_string(root.join("diff.rs")).expect("git/diff.rs");
    assert!(
        diff.contains("\"git diff source\"")
            && diff.contains("\"remaining changed lines\"")
            && diff.contains("record_git_cap_once("),
        "git diff aggregate cap hits must emit an operator-visible truncation error, not silently stop"
    );

    let history = std::fs::read_to_string(root.join("history.rs")).expect("git/history.rs");
    assert!(
        history.contains("record_git_history_cap_once(cap, &mut aggregate_cap_reported)"),
        "git history aggregate cap hits must emit the shared operator-visible truncation error"
    );

    let git_mod = std::fs::read_to_string(root.join("mod.rs")).expect("git/mod.rs");
    assert!(
        git_mod.contains("git source reached aggregate byte cap; remaining work was NOT scanned")
            && git_mod
                .contains("git source reached aggregate chunk cap; remaining work was NOT scanned")
            && git_mod.contains("crate::record_skip_event(crate::SourceSkipEvent::SourceTruncated)")
            && git_mod.contains("were not scanned"),
        "shared git cap reporter must warn, count partial coverage, and return an explicit SourceError"
    );
}

#[cfg(not(feature = "git"))]
#[test]
fn git_blob_caps_require_git_feature() {
    assert!(!cfg!(feature = "git"));
}
