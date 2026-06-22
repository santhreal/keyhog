//! Plain path/detector lines without metadata must load.

#[test]
fn allowlist_entries_without_metadata_load() {
    let al = keyhog_core::testing::CoreTestApi::allowlist_parse(
        &keyhog_core::testing::TestApi,
        "path:**/*.md
detector:demo
",
    );
    assert!(al.ignored_paths.iter().any(|p| p == "**/*.md"));
    assert!(al.ignored_detectors.contains("demo"));
}
