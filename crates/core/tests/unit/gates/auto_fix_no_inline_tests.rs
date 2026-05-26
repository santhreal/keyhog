//! Gate `auto_fix`: no inline #[cfg(test)] (Santh folder contract).

#[test]
fn auto_fix_no_inline_tests() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/auto_fix.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    assert!(
        !src.contains("#[cfg(test)]"),
        "auto_fix: move inline tests to crates/core/tests/"
    );
}
