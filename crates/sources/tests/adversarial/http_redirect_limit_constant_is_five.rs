//! Shared HTTP client redirect cap must stay at five hops.

#[test]
fn http_redirect_limit_constant_is_five() {
    let src_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let http = std::fs::read_to_string(src_root.join("http.rs")).expect("http.rs");
    let ssrf = std::fs::read_to_string(src_root.join("web/ssrf.rs")).expect("web/ssrf.rs");
    assert!(
        http.contains("pub(crate) const REDIRECT_LIMIT: usize = 5"),
        "redirect SSRF/bomb defense requires one 5-hop cap in http.rs"
    );
    assert!(
        http.contains("Policy::limited(REDIRECT_LIMIT)"),
        "both blocking and async builders must use limited redirect policy"
    );
    assert!(
        ssrf.contains("use crate::http::REDIRECT_LIMIT;") && !ssrf.contains("const REDIRECT_LIMIT"),
        "web SSRF redirect revalidation must import the shared redirect cap, not define its own"
    );
}
