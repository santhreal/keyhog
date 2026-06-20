#[test]
fn git_staged_excludes_use_empty_source_not_fake_path() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let sources = std::fs::read_to_string(root.join("src/sources.rs")).expect("read sources");

    assert!(
        !sources.contains(".keyhog-empty-staged-include-set"),
        "all-excluded --git-staged scans must not use a fake missing path as a sentinel"
    );
    assert!(
        sources.contains("struct EmptySource")
            && sources.contains("git-staged/excluded")
            && sources.contains("staged_include_set_exhausted"),
        "all-excluded --git-staged scans must route through the explicit empty source owner"
    );
}
