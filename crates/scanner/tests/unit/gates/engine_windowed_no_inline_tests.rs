//! Gate `engine::windowed`: no inline #[cfg(test)] (Santh folder contract).

#[test]
fn engine_windowed_no_inline_tests() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/engine/windowed.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    assert!(
        !src.contains("#[cfg(test)]"),
        "engine::windowed: move inline tests to crates/scanner/tests/"
    );
}
