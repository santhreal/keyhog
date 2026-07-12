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

#[test]
fn dns_pinned_rebuild_neutralizes_ambient_proxy() {
    // The DNS-pinned direct rebuild delegates to the single-owner
    // `build_pinned_verifier_client` (lib.rs), which must call `.no_proxy()`
    // BEFORE `.resolve_to_addrs(...)` so an ambient env proxy can never bypass
    // the pinned DNS result.
    let req = include_str!("../../../src/verify/request.rs");
    assert!(
        req.split("fn build_pinned_client(")
            .nth(1)
            .expect("request.rs must own build_pinned_client")
            .contains("crate::build_pinned_verifier_client("),
        "build_pinned_client must route through the single-owner pinned client builder"
    );

    let lib = include_str!("../../../src/lib.rs");
    let pinned_builder = lib
        .split("fn build_pinned_verifier_client(")
        .nth(1)
        .expect("lib.rs must own build_pinned_verifier_client")
        .split(".resolve_to_addrs(host, pinned_addrs)")
        .next()
        .expect("pinned client builder must call resolve_to_addrs");

    assert!(
        pinned_builder.contains(".no_proxy()"),
        "DNS-pinned direct verifier client must disable ambient proxy env before \
         resolve_to_addrs, or env proxies bypass the pinned DNS result"
    );
}
