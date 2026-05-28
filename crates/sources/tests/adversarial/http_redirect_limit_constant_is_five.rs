//! Shared HTTP client redirect cap must stay at five hops.

#[test]
fn http_redirect_limit_constant_is_five() {
    let src = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/http.rs"))
        .expect("http.rs");
    assert!(
        src.contains("const REDIRECT_LIMIT: usize = 5"),
        "redirect SSRF/bomb defense requires 5-hop cap in http.rs"
    );
    assert!(
        src.contains("Policy::limited(REDIRECT_LIMIT)"),
        "both blocking and async builders must use limited redirect policy"
    );
}
