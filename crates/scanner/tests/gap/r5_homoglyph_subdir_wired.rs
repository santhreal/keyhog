//! KH-GAP-151: homoglyph subdir wired.

#[test]
fn r5_homoglyph_subdir_wired() {
    let mod_rs = include_str!("../adversarial/mod.rs");
    assert!(
        mod_rs.contains("pub mod homoglyph;"),
        "KH-GAP-151: homoglyph not wired"
    );
}
