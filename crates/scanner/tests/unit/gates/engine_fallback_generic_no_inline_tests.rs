//! Gate `engine::fallback_generic`: no inline #[cfg(test)] (Santh folder contract).

#[test]
fn engine_fallback_generic_no_inline_tests() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/engine/fallback_generic.rs"
    );
    let src = std::fs::read_to_string(path).expect("source readable");
    assert!(
        !src.contains("#[cfg(test)]"),
        "engine::fallback_generic: move inline tests to crates/scanner/tests/"
    );
}
