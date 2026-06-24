use keyhog_sources::skip_counts;
use keyhog_sources::testing::{SourceTestApi, TestApi};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;

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

#[test]
fn cloud_transport_failures_count_as_unreadable_objects() {
    let _guard = TestApi.skip_counter_guard();
    TestApi.reset_skip_counters();

    let err = TestApi.cloud_record_unreadable_object_skip(
        "unit-cloud",
        "object",
        "cloud://bucket/missing.txt",
        "download failed: connection refused",
    );

    let message = err.to_string();
    assert!(
        message.contains("download failed: connection refused")
            && message.contains("cloud://bucket/missing.txt")
            && message.contains("object was not scanned"),
        "unexpected cloud transport error: {message}"
    );
    let counts = skip_counts();
    assert_eq!(
        counts.unreadable, 1,
        "cloud download transport failures must be counted as unreadable coverage gaps"
    );
    assert_eq!(
        counts.over_max_size, 0,
        "download transport failures must not pollute size-cap accounting"
    );
    assert_eq!(
        counts.binary, 0,
        "download transport failures must not pollute binary-skip accounting"
    );
}

#[test]
fn cloud_body_stream_errors_count_as_unreadable_objects() {
    let _guard = TestApi.skip_counter_guard();
    TestApi.reset_skip_counters();

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind local truncated-body server");
    let addr = listener
        .local_addr()
        .expect("local truncated-body server address");
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept one cloud body request");
        let mut request = [0_u8; 512];
        let _ = stream.read(&mut request);
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\n\
                  Content-Type: text/plain\r\n\
                  Content-Length: 64\r\n\
                  Connection: close\r\n\
                  \r\n\
                  partial",
            )
            .expect("write truncated cloud body response");
    });

    let err = TestApi
        .cloud_read_text_object_body_from_url(&format!("http://{addr}/truncated.txt"), 1024)
        .expect_err("truncated cloud response body must emit SourceError");
    server.join().expect("truncated-body server thread");

    let message = err.to_string();
    assert!(
        message.contains("failed to read body")
            && message.contains("truncated.txt")
            && message.contains("object was not scanned"),
        "unexpected cloud body read error: {message}"
    );
    let counts = skip_counts();
    assert_eq!(
        counts.unreadable, 1,
        "cloud body read failures must be counted as unreadable coverage gaps"
    );
    assert_eq!(
        counts.over_max_size, 0,
        "body read failures must not pollute size-cap accounting"
    );
}
