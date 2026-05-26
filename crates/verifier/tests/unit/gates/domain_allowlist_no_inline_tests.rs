//! Gate `domain_allowlist`: no inline #[cfg(test)] (Santh folder contract).

#[test]
fn domain_allowlist_no_inline_tests() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/domain_allowlist.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    assert!(
        !src.contains("#[cfg(test)]"),
        "domain_allowlist: move inline tests to crates/verifier/tests/"
    );
}
