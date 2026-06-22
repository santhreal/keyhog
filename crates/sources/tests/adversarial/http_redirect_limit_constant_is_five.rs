//! Shared HTTP client redirect cap must stay at five hops.

#[test]
fn http_redirect_limit_constant_is_five() {
    let src_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let http = std::fs::read_to_string(src_root.join("http.rs")).expect("http.rs");
    let web = std::fs::read_to_string(src_root.join("web.rs")).expect("web.rs");
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
        web.contains("send_with_pinned_redirects")
            && web.contains("crate::http::REDIRECT_LIMIT")
            && web.contains("build_web_client("),
        "WebSource redirects must use the shared cap and rebuild a pinned client for every hop"
    );
    assert!(
        ssrf.contains("Policy::none()") && !ssrf.contains("Policy::custom"),
        "WebSource clients must disable reqwest auto-redirects so manual pinned redirects own every hop"
    );
}
