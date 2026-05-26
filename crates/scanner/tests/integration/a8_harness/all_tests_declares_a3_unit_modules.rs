//! LR2-A8 harness integration: a3 unit modules remain in unified harness

#[test]
fn unit_mod_exports_a3_slices() {
    let src = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/unit/mod.rs"),
    )
    .expect("unit/mod.rs");
    for m in ["a3_decode", "a3_multiline", "a3_pipeline"] {
        assert!(src.contains(&format!("pub mod {m};")), "missing unit::{m}");
    }
}
