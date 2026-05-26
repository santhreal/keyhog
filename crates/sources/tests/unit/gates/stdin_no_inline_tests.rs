//! Gate `stdin`: no inline #[cfg(test)] (Santh folder contract).

#[test]
fn stdin_no_inline_tests() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/stdin.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    assert!(
        !src.contains("#[cfg(test)]"),
        "stdin: move inline tests to crates/sources/tests/"
    );
}
