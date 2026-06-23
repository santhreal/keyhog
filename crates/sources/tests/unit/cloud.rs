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
}

#[test]
fn cloud_binary_content_type_ignores_case_and_media_parameters() {
    assert!(TestApi.cloud_is_binary_content_type("Application/Zip; charset=binary"));
    assert!(TestApi.cloud_is_binary_content_type(" image/PNG ; name=x"));
    assert!(TestApi.cloud_is_binary_content_type("application/octet-stream"));
    assert!(!TestApi.cloud_is_binary_content_type("text/plain"));
    assert!(!TestApi.cloud_is_binary_content_type("application/json; charset=utf-8"));
}
