//! Archive open path must skip symlinked archive files.

#[test]
fn archive_symlink_guard_in_source() {
    let src = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/filesystem.rs"))
        .expect("filesystem.rs");
    assert!(
        src.contains("refusing to open archive at a symlink path"),
        "archive symlink guard log must exist"
    );
    assert!(
        src.contains("symlink_metadata(&path)"),
        "must check symlink_metadata before openpack"
    );
}
