//! Gate `hardening`: no inline #[cfg(test)] (Santh folder contract).

#[test]
fn hardening_no_inline_tests() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/hardening.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    assert!(
        !src.contains("#[cfg(test)]"),
        "hardening: move inline tests to crates/core/tests/"
    );
}
