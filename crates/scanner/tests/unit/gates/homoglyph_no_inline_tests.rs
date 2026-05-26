//! Gate `homoglyph`: no inline #[cfg(test)] (Santh folder contract).

#[test]
fn homoglyph_no_inline_tests() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/homoglyph.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    assert!(
        !src.contains("#[cfg(test)]"),
        "homoglyph: move inline tests to crates/scanner/tests/"
    );
}
