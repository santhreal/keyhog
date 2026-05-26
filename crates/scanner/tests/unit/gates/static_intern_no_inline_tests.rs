//! Gate `static_intern`: no inline #[cfg(test)] (Santh folder contract).

#[test]
fn static_intern_no_inline_tests() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/static_intern.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    assert!(
        !src.contains("#[cfg(test)]"),
        "static_intern: move inline tests to crates/scanner/tests/"
    );
}
