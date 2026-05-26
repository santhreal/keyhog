//! Gate `allowlist`: no inline #[cfg(test)] (Santh folder contract).

#[test]
fn allowlist_no_inline_tests() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/allowlist.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    assert!(
        !src.contains("#[cfg(test)]"),
        "allowlist: move inline tests to crates/core/tests/"
    );
}
