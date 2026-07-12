//! Archive open path must skip symlinked archive files.

#[test]
fn archive_symlink_guard_in_source() {
    let src = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/filesystem/extract/archive.rs"
    ))
    .expect("filesystem/extract/archive.rs");
    let parent = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/filesystem/extract.rs"
    ))
    .expect("filesystem/extract.rs");
    let filesystem =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/filesystem.rs"))
            .expect("filesystem.rs");
    assert!(
        src.contains("refusing to open archive at a symlink path"),
        "archive symlink guard log must exist"
    );
    assert!(
        parent.contains("std::fs::symlink_metadata(path)"),
        "symlink helper must use symlink_metadata without following links"
    );
    let guard = src
        .find("if is_symlink(path)")
        .expect("archive symlink guard");
    let open = src
        .find("openpack::OpenPack::open(path")
        .expect("archive open");
    assert!(
        guard < open,
        "must check symlink_metadata-backed guard before openpack"
    );
    // The expandable-extension set moved to the Tier-B
    // rules/expandable-symlink-extensions.toml owner that `EXPANDABLE_SYMLINK_EXTS`
    // reads; assert filesystem.rs wires that owner AND the owner lists every ext.
    assert!(
        filesystem.contains("EXPANDABLE_SYMLINK_EXTS"),
        "filesystem symlink guard must read the EXPANDABLE_SYMLINK_EXTS Tier-B owner"
    );
    let expandable_exts = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../rules/expandable-symlink-extensions.toml"
    ))
    .expect("rules/expandable-symlink-extensions.toml");
    for ext in [
        "har", "zip", "apk", "ipa", "crx", "jar", "tar", "gz", "tgz", "zst", "lz4", "sz", "bz2",
        "xz", "7z", "rar", "pdf",
    ] {
        assert!(
            expandable_exts.contains(ext),
            "explicit include symlink guard must cover expandable extension {ext:?} \
             (Tier-B rules/expandable-symlink-extensions.toml owner)"
        );
    }
}
