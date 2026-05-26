//! Superseded by binary_read_is_capped — kept as alias gate for unbounded read regression.

#[test]
fn binary_mod_has_no_unbounded_fs_read() {
    let src = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/binary/mod.rs"))
        .expect("binary/mod.rs");
    assert!(
        !src.contains("std::fs::read(&self.path)"),
        "must not use unbounded std::fs::read on binary path"
    );
}
