#[test]
fn http_proxy_flag_overrides_env() {
    std::env::set_var("KEYHOG_PROXY", "http://env:8080");
    let cfg = keyhog_sources::http::HttpClientConfig { proxy: Some("http://flag:9090".into()), ..Default::default() };
    assert_eq!(cfg.effective_proxy().as_deref(), Some("http://flag:9090"));
    std::env::remove_var("KEYHOG_PROXY");
}
