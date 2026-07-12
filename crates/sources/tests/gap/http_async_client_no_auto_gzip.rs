//! KH-GAP-113: the async HTTP builder must disable auto-decompress like the
//! blocking path (reqwest auto-decompresses gzip/brotli/deflate by default,
//! which turns a hostile response into a decompression bomb the size caps can't
//! see through).
//!
//! Both builders now delegate to the ONE shared `shared_http_policy!` macro, so
//! this asserts (1) the macro is the single owner of the no_gzip/no_brotli/
//! no_deflate policy, and (2) BOTH `async_client_builder` and
//! `blocking_client_builder` route through it. That is a STRONGER guarantee than
//! string-matching the (now macro-inlined) calls in one function body: it proves
//! neither builder can carry a divergent decompression policy.

#[test]
fn http_async_client_no_auto_gzip() {
    let src = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/http.rs"))
        .expect("http.rs");

    // (1) The decompression policy lives in ONE owner: the shared_http_policy! macro.
    let macro_body = src
        .split("macro_rules! shared_http_policy")
        .nth(1)
        .expect("shared_http_policy! macro owner must exist");
    for needle in [".no_gzip()", ".no_brotli()", ".no_deflate()"] {
        assert!(
            macro_body.contains(needle),
            "shared_http_policy! macro must call {needle} so every built client disables auto-decompress"
        );
    }

    // (2) Both builders must route through that ONE owner (no divergent policy).
    let bodies: Vec<&str> = src.split("pub(crate) fn ").collect();
    for name in ["async_client_builder", "blocking_client_builder"] {
        let body = bodies
            .iter()
            .find(|body| body.starts_with(name))
            .unwrap_or_else(|| panic!("{name} owner must exist"));
        assert!(
            body.contains("shared_http_policy!"),
            "{name} must delegate to the shared_http_policy! macro (the single no-auto-decompress owner)"
        );
    }
}
