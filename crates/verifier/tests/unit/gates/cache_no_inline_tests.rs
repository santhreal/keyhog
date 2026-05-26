//! Gate `cache`: no inline #[cfg(test)] (Santh folder contract).

#[test]
fn cache_no_inline_tests() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/cache.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    assert!(
        !src.contains("#[cfg(test)]"),
        "cache: move inline tests to crates/verifier/tests/"
    );
}
