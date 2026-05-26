//! Web fetch must cap raw response bytes; gzip auto-decompress disabled via http.rs.

#[cfg(feature = "web")]
#[test]
fn web_max_response_bytes_in_source() {
    let src = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/web.rs"))
        .expect("web.rs");
    assert!(src.contains("MAX_RESPONSE_BYTES"), "response cap required");
    assert!(
        src.contains("10 * 1024 * 1024"),
        "web response cap must remain 10 MiB"
    );
    assert!(
        src.contains(".take(MAX_RESPONSE_BYTES"),
        "response body read must use take() before buffering"
    );

    let http = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/http.rs"))
        .expect("http.rs");
    assert!(
        http.contains(".no_gzip()"),
        "shared HTTP builder must disable auto gzip (web uses http.rs)"
    );
}

#[cfg(not(feature = "web"))]
#[test]
fn web_max_response_requires_web_feature() {
    assert!(!cfg!(feature = "web"));
}
