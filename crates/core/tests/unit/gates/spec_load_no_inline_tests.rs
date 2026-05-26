//! Gate `spec::load`: no inline #[cfg(test)] (Santh folder contract).

#[test]
fn spec_load_no_inline_tests() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/spec/load.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    assert!(
        !src.contains("#[cfg(test)]"),
        "spec::load: move inline tests to crates/core/tests/"
    );
}
