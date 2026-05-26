//! Gate `shared_regexes`: no inline #[cfg(test)] (Santh folder contract).

#[test]
fn shared_regexes_no_inline_tests() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/shared_regexes.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    assert!(
        !src.contains("#[cfg(test)]"),
        "shared_regexes: move inline tests to crates/scanner/tests/"
    );
}
