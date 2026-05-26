//! Gate `compiler_prefix`: no inline #[cfg(test)] (Santh folder contract).

#[test]
fn compiler_prefix_no_inline_tests() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/compiler_prefix.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    assert!(
        !src.contains("#[cfg(test)]"),
        "compiler_prefix: move inline tests to crates/scanner/tests/"
    );
}
