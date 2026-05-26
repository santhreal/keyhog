//! Gate `multiline::fragment_cache`: no inline #[cfg(test)] (Santh folder contract).

#[test]
fn multiline_fragment_cache_no_inline_tests() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/multiline/fragment_cache.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    assert!(
        !src.contains("#[cfg(test)]"),
        "multiline::fragment_cache: move inline tests to crates/scanner/tests/"
    );
}
