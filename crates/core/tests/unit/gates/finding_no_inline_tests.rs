//! Gate `finding`: no inline #[cfg(test)] (Santh folder contract).

#[test]
fn finding_no_inline_tests() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/finding.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    assert!(
        !src.contains("#[cfg(test)]"),
        "finding: move inline tests to crates/core/tests/"
    );
}
