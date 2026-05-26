//! Gate `rate_limit`: no inline #[cfg(test)] (Santh folder contract).

#[test]
fn rate_limit_no_inline_tests() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/rate_limit.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    assert!(
        !src.contains("#[cfg(test)]"),
        "rate_limit: move inline tests to crates/verifier/tests/"
    );
}
