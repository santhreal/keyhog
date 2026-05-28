#[test]
fn http_proxy_off_preserved() {let cfg = keyhog_sources::http::HttpClientConfig { proxy: Some("off".into()), ..Default::default() }; assert_eq!(cfg.effective_proxy().as_deref(), Some("off"));}
