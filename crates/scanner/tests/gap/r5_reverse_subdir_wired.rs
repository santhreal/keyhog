//! KH-GAP-153: reverse subdir wired.

#[test]
fn r5_reverse_subdir_wired() {
    let mod_rs = include_str!("../adversarial/mod.rs");
    assert!(
        mod_rs.contains("pub mod reverse;"),
        "KH-GAP-153: reverse not wired"
    );
}
