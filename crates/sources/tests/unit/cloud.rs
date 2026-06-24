use keyhog_sources::skip_counts;
use keyhog_sources::testing::{SourceTestApi, TestApi};

#[test]
fn cloud_object_key_binary_extension_check_is_case_insensitive_without_text_loss() {
    assert!(!TestApi.cloud_is_probably_text_object_key("assets/IMAGE.PNG"));
    assert!(!TestApi.cloud_is_probably_text_object_key("archives/release.TAR"));
    assert!(!TestApi.cloud_is_probably_text_object_key("archives/release.RAR"));
    assert!(!TestApi.cloud_is_probably_text_object_key("fonts/site.WOFF2"));
    assert!(!TestApi.cloud_is_probably_text_object_key("native/tool.EXE"));
    assert!(!TestApi.cloud_is_probably_text_object_key("database/cache.SQLITE"));
    assert!(TestApi.cloud_is_probably_text_object_key("configs/secrets.TXT"));
    assert!(TestApi.cloud_is_probably_text_object_key("Makefile"));
    assert!(TestApi.cloud_is_probably_text_object_key("dir.with.dot/Makefile"));
    assert!(TestApi.cloud_is_probably_text_object_key("configs/.env"));
    assert!(TestApi.cloud_is_probably_text_object_key("configs/name."));
    assert!(!TestApi.cloud_is_probably_text_object_key("windows\\named\\payload.EXE"));
}

#[test]
fn cloud_binary_content_type_ignores_case_and_media_parameters() {
    assert!(TestApi.cloud_is_binary_content_type("Application/Zip; charset=binary"));
    assert!(TestApi.cloud_is_binary_content_type(" image/PNG ; name=x"));
    assert!(!TestApi.cloud_is_binary_content_type("application/octet-stream"));
    assert!(!TestApi.cloud_is_binary_content_type("text/plain"));
    assert!(!TestApi.cloud_is_binary_content_type("application/json; charset=utf-8"));
}

#[test]
fn cloud_text_object_content_length_over_cap_yields_source_error() {
    let _guard = TestApi.skip_counter_guard();
    TestApi.reset_skip_counters();

    let server = httpmock::MockServer::start();
    let mock = server.mock(|when, then| {
        when.method(httpmock::Method::GET).path("/huge.txt");
        then.status(200)
            .header("content-type", "text/plain")
            .body("abcdef");
    });

    let err = TestApi
        .cloud_read_text_object_body_from_url(&server.url("/huge.txt"), 3)
        .expect_err("over-cap cloud object must emit SourceError");

    mock.assert();
    let message = err.to_string();
    assert!(
        message.contains("Content-Length 6 exceeds the per-object byte cap 3")
            && message.contains("huge.txt")
            && message.contains("object was not scanned"),
        "unexpected cloud cap error: {message}"
    );
    assert_eq!(skip_counts().over_max_size, 1);
}
