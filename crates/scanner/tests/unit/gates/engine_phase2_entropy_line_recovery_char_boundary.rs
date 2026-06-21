//! `phase2_entropy` fallback line recovery must not slice at an unchecked byte offset.

#[test]
fn entropy_line_recovery_snaps_fallback_offset_to_char_boundary() {
    let source = include_str!("../../../src/engine/phase2_entropy/gates.rs");
    assert!(
        source.contains("floor_char_boundary(")
            && source.contains("entropy_match.offset.min(preprocessed.text.len())"),
        "entropy fallback line recovery must snap entropy_match.offset to a char boundary before slicing"
    );
    for forbidden in ["preprocessed.text[..offset]", "preprocessed.text[offset..]"] {
        assert!(
            !source.contains(forbidden),
            "entropy fallback line recovery must not slice with unchecked `{forbidden}`"
        );
    }
}
