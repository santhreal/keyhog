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
        src.contains("std::fs::symlink_metadata(path)"),
        "symlink helper must use symlink_metadata without following links"
    );
    let guard = src
        .find("if is_symlink(&path)")
        .expect("archive symlink guard");
    let open = src
        .find("openpack::OpenPack::open_default(&path)")
        .expect("archive open");
    assert!(
        guard < open,
        "must check symlink_metadata-backed guard before openpack"
    );
}
