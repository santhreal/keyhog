//! Path globs with oversized segments must not match (DoS guard).

#[test]
fn allowlist_oversized_glob_segment_does_not_match() {
    let huge = "a".repeat(2048);
    let pattern = format!("{huge}/*.txt");
    let al = keyhog_core::testing::CoreTestApi::allowlist_parse(
        &keyhog_core::testing::TestApi,
        &format!("path:{pattern}"),
    );
    assert!(
        !al.is_path_ignored("anything.txt"),
        "oversized segment glob must not match"
    );
}
