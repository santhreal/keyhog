//! Migrated from `src/report/sarif.rs` inline tests.
#[test]
fn sarif_uri_relative_path_passes_through() {
    assert_eq!(
        keyhog_core::testing::CoreTestApi::file_path_to_sarif_uri(
            &keyhog_core::testing::TestApi,
            "config.env"
        ),
        "config.env"
    );
    assert_eq!(
        keyhog_core::testing::CoreTestApi::file_path_to_sarif_uri(
            &keyhog_core::testing::TestApi,
            "src/lib.rs"
        ),
        "src/lib.rs"
    );
    assert_eq!(
        keyhog_core::testing::CoreTestApi::file_path_to_sarif_uri(
            &keyhog_core::testing::TestApi,
            "a/b/c.txt"
        ),
        "a/b/c.txt"
    );
}
