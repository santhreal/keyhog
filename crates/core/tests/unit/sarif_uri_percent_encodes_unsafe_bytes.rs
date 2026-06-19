//! Migrated from `src/report/sarif.rs` inline tests.
#[test]
fn sarif_uri_percent_encodes_unsafe_bytes() {
    assert_eq!(
        keyhog_core::testing::CoreTestApi::file_path_to_sarif_uri(
            &keyhog_core::testing::TestApi,
            "/tmp/file with space.env"
        ),
        "file:///tmp/file%20with%20space.env"
    );
    assert_eq!(
        keyhog_core::testing::CoreTestApi::file_path_to_sarif_uri(
            &keyhog_core::testing::TestApi,
            "/tmp/réport.json"
        ),
        "file:///tmp/r%C3%A9port.json"
    );
    assert_eq!(
        keyhog_core::testing::CoreTestApi::file_path_to_sarif_uri(
            &keyhog_core::testing::TestApi,
            "/tmp/foo?bar#baz"
        ),
        "file:///tmp/foo%3Fbar%23baz"
    );
}
