//! Web fetch must cap raw response bytes and explicit Content-Encoding decode.

#[cfg(feature = "web")]
#[test]
fn web_max_response_bytes_in_source() {
    let src = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/web.rs"))
        .expect("web.rs");
    assert!(
        !src.contains("MAX_RESPONSE_BYTES"),
        "web response cap must be owned by SourceLimits, not a private source constant"
    );
    assert!(
        src.contains("max_response_bytes")
            && src.contains("crate::capped_read::read_to_cap(resp, cap")
            && src.contains("crate::capped_read::read_to_cap(")
            && src.contains("read.truncated"),
        "response body and Content-Encoding decode reads must route through the shared capped-read owner"
    );
    assert!(
        src.contains("fn decode_content_encoding")
            && src.contains("decoded {encoding} response")
            && src.contains("Content-Encoding"),
        "web response handling must explicitly decode gzip/br/deflate behind the same cap"
    );
    let limits = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/limits.rs"))
        .expect("limits.rs");
    assert!(
        limits.contains("web_response_bytes: 10 * 1024 * 1024"),
        "web response default cap must remain 10 MiB in SourceLimits"
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
