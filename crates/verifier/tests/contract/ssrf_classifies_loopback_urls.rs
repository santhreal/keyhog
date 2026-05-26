use keyhog_verifier::ssrf::is_private_url;

#[test]
fn ssrf_classifies_loopback_urls_as_private() {
    for url in [
        "http://127.0.0.1/",
        "http://2130706433/",
        "http://0x7f000001/",
    ] {
        assert!(is_private_url(url), "loopback URL {url} must classify private");
    }
}
