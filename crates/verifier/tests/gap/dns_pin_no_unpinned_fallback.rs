//! KH-GAP-120: DNS pin build failure must not fall back to unpinned base client.

#[test]
fn dns_pin_no_unpinned_fallback() {
    let src = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/verify/request.rs"
    ))
    .expect("request.rs");
    assert!(
        src.contains("resolve_to_addrs"),
        "DNS pinning via resolve_to_addrs required"
    );
    assert!(
        !src.contains("Fall back to the shared client"),
        "unpinned fallback re-opens DNS rebinding window"
    );
    assert!(
        src.contains("DNS pin client build failed"),
        "pin build failure must surface as blocked error, not silent fallback"
    );
}
