//! Web fetch must cap raw response bytes and explicit Content-Encoding decode.

#[cfg(not(feature = "web"))]
#[test]
fn web_max_response_requires_web_feature() {
    assert!(!cfg!(feature = "web"));
}
