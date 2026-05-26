//! Gate `registry`: no inline #[cfg(test)] (Santh folder contract).

#[test]
fn registry_no_inline_tests() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/registry.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    assert!(
        !src.contains("#[cfg(test)]"),
        "registry: move inline tests to crates/core/tests/"
    );
}
