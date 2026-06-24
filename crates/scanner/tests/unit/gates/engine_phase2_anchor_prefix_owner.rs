//! Gate `engine::phase2_anchor`: shared-anchor localization must use the same
//! required-prefix proof owner as the phase-2 no-candidate gate.

#[test]
fn engine_phase2_anchor_prefix_owner() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/engine/phase2_anchor.rs");
    let src = std::fs::read_to_string(path).expect("phase2_anchor source readable");
    assert!(
        src.contains("use super::phase2::{")
            && src.contains("gate_prefix_literals")
            && src.contains("MIN_PREFIX_BYTES")
            && src.contains("CONFIRMED_MAX_LITERALS_PER_PATTERN")
            && src.contains("required_prefix_literals_with_cap")
            && src.contains("let literals = gate_prefix_literals(src)?;"),
        "phase2 anchor extraction must reuse the phase2 gate_prefix_literals owner"
    );

    let extractor = src
        .split("pub(crate) fn required_prefix_literals")
        .nth(1)
        .expect("required_prefix_literals exists");
    assert!(
        !extractor.contains("ParserBuilder::new()") && !extractor.contains(".case_insensitive("),
        "required_prefix_literals must not carry a second regex-syntax parser contract"
    );
}
