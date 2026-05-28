//! KH-GAP-152: concat subdir wired.

#[test]
fn r5_concat_subdir_wired() {
    let mod_rs = include_str!("../adversarial/mod.rs");
    assert!(mod_rs.contains("pub mod concat;"), "KH-GAP-152: concat not wired");
}
