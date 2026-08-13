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
            && src.contains("FILE_FLAG_OPEN_REPARSE_POINT")
            && src.contains("metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0")
            && src.contains("refusing to follow symlink or junction (Windows safety guard)")
            && !src.contains("std::fs::symlink_metadata(path)"),
        "Windows open_file_safe must inspect the opened reparse-point handle so path swaps and junctions cannot bypass no-follow"
    );
}
