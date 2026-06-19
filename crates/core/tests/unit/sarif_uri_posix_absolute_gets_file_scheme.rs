//! Migrated from `src/report/sarif.rs` inline tests.
#[test]
fn sarif_uri_posix_absolute_gets_file_scheme() {
    assert_eq!(
        keyhog_core::testing::CoreTestApi::file_path_to_sarif_uri(
            &keyhog_core::testing::TestApi,
            "/etc/secrets.env"
        ),
        "file:///etc/secrets.env"
    );
    assert_eq!(
        keyhog_core::testing::CoreTestApi::file_path_to_sarif_uri(
            &keyhog_core::testing::TestApi,
            "/home/u/.aws/credentials"
        ),
        "file:///home/u/.aws/credentials"
    );
}
