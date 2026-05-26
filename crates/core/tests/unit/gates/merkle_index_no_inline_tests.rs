//! Gate `merkle_index`: no inline #[cfg(test)] (Santh folder contract).

#[test]
fn merkle_index_no_inline_tests() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/merkle_index.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    assert!(
        !src.contains("#[cfg(test)]"),
        "merkle_index: move inline tests to crates/core/tests/"
    );
}
