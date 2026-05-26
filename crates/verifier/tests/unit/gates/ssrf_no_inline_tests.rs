//! Gate `ssrf`: no inline #[cfg(test)] (Santh folder contract).

#[test]
fn ssrf_no_inline_tests() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/ssrf.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    assert!(
        !src.contains("#[cfg(test)]"),
        "ssrf: move inline tests to crates/verifier/tests/"
    );
}
