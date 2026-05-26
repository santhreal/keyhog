//! Gate `config`: no inline #[cfg(test)] (Santh folder contract).

#[test]
fn config_no_inline_tests() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/config.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    assert!(
        !src.contains("#[cfg(test)]"),
        "config: move inline tests to crates/core/tests/"
    );
}
