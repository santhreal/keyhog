//! Gate `engine::segment_attribution`: no inline #[cfg(test)] (Santh folder contract).

#[test]
fn engine_segment_attribution_no_inline_tests() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/engine/segment_attribution.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    assert!(
        !src.contains("#[cfg(test)]"),
        "engine::segment_attribution: move inline tests to crates/scanner/tests/"
    );
}
