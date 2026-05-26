//! Gate `safe_bin`: no inline #[cfg(test)] (Santh folder contract).

#[test]
fn safe_bin_no_inline_tests() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/safe_bin.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    assert!(
        !src.contains("#[cfg(test)]"),
        "safe_bin: move inline tests to crates/core/tests/"
    );
}
