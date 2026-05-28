//! KH-GAP-150: chunk_boundary subdir wired.

#[test]
fn r5_chunk_boundary_subdir_wired() {
    let mod_rs = include_str!("../adversarial/mod.rs");
    assert!(
        mod_rs.contains("pub mod chunk_boundary;"),
        "KH-GAP-150: chunk_boundary not wired"
    );
}
