//! Shared HTTP builder must disable auto gzip to prevent body bombs.

#[test]
fn http_client_no_auto_gzip() {
    let src = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/http.rs"
    ))
    .expect("http.rs");
    assert!(
        src.contains(".no_gzip()"),
        "HttpClientConfig builder must disable auto gzip"
    );
}
