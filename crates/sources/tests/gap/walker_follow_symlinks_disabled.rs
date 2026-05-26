//! Directory walker must not follow symlinks out of scan root.

#[test]
fn walker_follow_symlinks_disabled() {
    let src = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/filesystem.rs"))
        .expect("filesystem.rs");
    assert!(
        src.contains(".follow_symlinks(false)"),
        "codewalk must set follow_symlinks(false)"
    );
}
