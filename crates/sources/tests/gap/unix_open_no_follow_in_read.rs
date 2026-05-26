//! Unix file open must use O_NOFOLLOW to refuse symlink traversal.

#[test]
fn unix_open_no_follow_in_read() {
    let src = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/filesystem/read.rs"
    ))
    .expect("read.rs");
    assert!(
        src.contains("O_NOFOLLOW"),
        "open_file_safe must set O_NOFOLLOW on unix"
    );
}
