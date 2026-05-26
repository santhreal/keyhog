//! Gate `multiline::config`: no inline #[cfg(test)] (Santh folder contract).

#[test]
fn multiline_config_no_inline_tests() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/multiline/config.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    assert!(
        !src.contains("#[cfg(test)]"),
        "multiline::config: move inline tests to crates/scanner/tests/"
    );
}
