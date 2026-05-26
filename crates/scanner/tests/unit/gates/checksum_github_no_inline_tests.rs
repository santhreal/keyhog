//! Gate `checksum::github`: no inline #[cfg(test)] (Santh folder contract).

#[test]
fn checksum_github_no_inline_tests() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/checksum/github.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    assert!(
        !src.contains("#[cfg(test)]"),
        "checksum::github: move inline tests to crates/scanner/tests/"
    );
}
