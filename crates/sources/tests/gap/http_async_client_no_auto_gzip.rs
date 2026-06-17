//! KH-GAP-113: async HTTP builder must disable auto-decompress like blocking path.

#[test]
fn http_async_client_no_auto_gzip() {
    let src = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/http.rs"))
        .expect("http.rs");
    let async_fn = src
        .split("fn async_client_builder")
        .nth(1)
        .expect("async_client_builder owner must exist");
    let async_body = async_fn
        .split("pub fn ")
        .next()
        .expect("async_client_builder body");
    for needle in [".no_gzip()", ".no_brotli()", ".no_deflate()"] {
        assert!(
            async_body.contains(needle),
            "async_client_builder must call {needle}"
        );
    }
}
