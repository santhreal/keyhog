//! Migrated from `src/report/sarif.rs` inline tests.
#[test]
fn sarif_uri_windows_absolute_normalises_backslashes() {
    assert_eq!(
        keyhog_core::testing::CoreTestApi::file_path_to_sarif_uri(
            &keyhog_core::testing::TestApi,
            "C:\\Users\\bob\\.aws\\creds"
        ),
        "file:///C:/Users/bob/.aws/creds"
    );
    assert_eq!(
        keyhog_core::testing::CoreTestApi::file_path_to_sarif_uri(
            &keyhog_core::testing::TestApi,
            "D:/secrets/key.pem"
        ),
        "file:///D:/secrets/key.pem"
    );
}
