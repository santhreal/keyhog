//! Gate `main`: no inline #[cfg(test)] (Santh folder contract).

#[test]
fn main_no_inline_tests() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/main.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    assert!(
        !src.contains("#[cfg(test)]"),
        "main: move inline tests to crates/cli/tests/"
    );
}
