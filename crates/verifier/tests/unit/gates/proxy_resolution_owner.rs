#[test]
fn proxy_resolution_has_one_mode_owner() {
    let src = include_str!("../../../src/lib.rs");
    assert!(
        src.contains("enum ProxyMode"),
        "verifier proxy resolution must classify modes through one owner enum"
    );
    assert!(
        src.contains("fn resolve_proxy_mode"),
        "apply_proxy_config and proxy_is_active must share one resolver"
    );
    assert_eq!(
        src.matches("resolve_proxy_mode(explicit)").count(),
        2,
        "apply_proxy_config and proxy_is_active should each call the shared resolver"
    );
    assert_eq!(
        src.matches("\"off\" | \"none\" | \"\"").count(),
        1,
        "off/none/empty sentinel parsing must live only in proxy_mode_from_raw"
    );
    // Config-policy mandate: the verifier proxy resolver must NOT read any
    // environment variable. Only the explicit --proxy / TOML value sets a proxy;
    // ambient KEYHOG_PROXY / HTTPS_PROXY / HTTP_PROXY / ALL_PROXY are neutralized
    // (`.no_proxy()`) so they can never silently reroute secret-bearing traffic.
    for forbidden in ["KEYHOG_PROXY", "HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY"] {
        assert!(
            !src.contains(forbidden),
            "verifier lib.rs must not reference the proxy env var {forbidden:?} \
             (config-policy mandate: env must never change behavior)"
        );
    }
}
