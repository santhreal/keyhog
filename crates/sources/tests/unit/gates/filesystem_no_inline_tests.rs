//! Gate `filesystem`: no inline #[cfg(test)] (Santh folder contract).

#[test]
fn filesystem_no_inline_tests() {
    for rel in [
        "src/filesystem.rs",
        "src/filesystem/extract.rs",
        "src/filesystem/filter.rs",
    ] {
        let path = format!("{}/{}", env!("CARGO_MANIFEST_DIR"), rel);
        let src = std::fs::read_to_string(&path).expect("source readable");
        assert!(
            !src.contains("#[cfg(test)]"),
            "filesystem: move inline tests from {rel} to crates/sources/tests/"
        );
    }
}
