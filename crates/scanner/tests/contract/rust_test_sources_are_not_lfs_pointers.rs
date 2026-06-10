//! Contract: Rust test targets must be real Rust source, not Git LFS pointers.

use std::path::PathBuf;

fn scanner_tests_dir() -> PathBuf {
    let mut dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    dir.push("tests");
    dir
}

#[test]
fn rust_test_sources_are_not_lfs_pointers() {
    let tests_dir = scanner_tests_dir();
    let mut pointer_files = Vec::new();

    for entry in std::fs::read_dir(&tests_dir).expect("scanner tests directory readable") {
        let entry = entry.expect("scanner tests directory entry readable");
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("rs") {
            continue;
        }

        let source = std::fs::read_to_string(&path).unwrap_or_else(|e| {
            panic!("failed to read Rust test source {}: {e}", path.display())
        });
        if source.starts_with("version https://git-lfs.github.com/spec/v1") {
            pointer_files.push(path);
        }
    }

    assert!(
        pointer_files.is_empty(),
        "Rust test files must not be Git LFS pointers: {:?}",
        pointer_files
    );
}
