//! Gate `engine::hot_patterns`: no inline #[cfg(test)] (Santh folder contract).

#[test]
fn engine_hot_patterns_no_inline_tests() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/engine/hot_patterns.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    assert!(
        !src.contains("#[cfg(test)]"),
        "engine::hot_patterns: move inline tests to crates/scanner/tests/"
    );
}
