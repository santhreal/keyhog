//! Contract for `web::redirect_pin_key` (reached via the `SourceTestApi`
//! facade), the function that derives the connection-reuse pin key for a web
//! redirect hop. Migrated out of an inline `#[cfg(test)]` block in
//! `src/web.rs` to satisfy the sources folder contract (`web_no_inline_tests`).
//!
//! The load-bearing property is that the pin key is the `host:port` authority,
//! so a same-host redirect (only the path changes) reuses ONE client, while a
//! different host OR port forces a rebuild (the pin carries the port). An
//! unparseable URL yields no pin key.

use keyhog_sources::testing::{SourceTestApi, TestApi};

#[test]
fn same_host_different_path_shares_one_pin_key() {
    // A same-host redirect (only the path changes) yields an identical pin
    // key, so the client is reused across the hop instead of rebuilt.
    assert_eq!(
        TestApi.redirect_pin_key("https://cdn.example.com/a.js"),
        TestApi.redirect_pin_key("https://cdn.example.com/b/c.map"),
    );
    assert_eq!(
        TestApi
            .redirect_pin_key("https://cdn.example.com/a.js")
            .as_deref(),
        Some("cdn.example.com:443"),
    );
}

#[test]
fn different_host_or_port_forces_a_rebuild() {
    let a = TestApi.redirect_pin_key("https://a.example.com/x");
    let b = TestApi.redirect_pin_key("https://b.example.com/x");
    assert_ne!(a, b);
    // Same host, different port must NOT share a pin (the resolve_to_addrs
    // pin carries the port).
    assert_eq!(
        TestApi
            .redirect_pin_key("https://a.example.com/x")
            .as_deref(),
        Some("a.example.com:443"),
    );
    assert_eq!(
        TestApi
            .redirect_pin_key("http://a.example.com/x")
            .as_deref(),
        Some("a.example.com:80"),
    );
}

#[test]
fn unparseable_url_has_no_pin_key() {
    assert_eq!(TestApi.redirect_pin_key("not a url"), None);
}
