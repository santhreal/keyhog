//! File opens must refuse symlink traversal on Unix and Windows.

#[test]
fn unix_open_no_follow_in_read() {
    let src = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/filesystem/read/raw.rs"
    ))
    .expect("read/raw.rs");
    assert!(
        src.contains("O_NOFOLLOW"),
        "open_file_safe must set O_NOFOLLOW on unix"
    );
    assert!(
        src.contains("#[cfg(windows)]")
            && src.contains("let meta = std::fs::symlink_metadata(path)?;")
            && src.contains("refusing to follow symlink (Windows safety guard)")
            && !src.contains("cannot classify path before Windows no-follow open")
            && !src.contains("if let Ok(meta) = std::fs::symlink_metadata(path)"),
        "Windows open_file_safe must fail closed while preserving symlink_metadata's original io::Error before the normal open"
    );
}
