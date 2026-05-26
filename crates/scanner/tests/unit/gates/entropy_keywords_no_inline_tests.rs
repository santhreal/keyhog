//! Gate `entropy::keywords`: no inline #[cfg(test)] (Santh folder contract).

#[test]
fn entropy_keywords_no_inline_tests() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/entropy/keywords.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    assert!(
        !src.contains("#[cfg(test)]"),
        "entropy::keywords: move inline tests to crates/scanner/tests/"
    );
}
