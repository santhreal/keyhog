//! Gate `encoding`: no inline #[cfg(test)] (Santh folder contract).

#[test]
fn encoding_no_inline_tests() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/encoding.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    assert!(
        !src.contains("#[cfg(test)]"),
        "encoding: move inline tests to crates/core/tests/"
    );
}
