//! Deep directory nesting must not stack-overflow the walker.

use super::support::collect_chunks;
use keyhog_sources::FilesystemSource;

#[test]
fn deeply_nested_dirs_scan_continues() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut path = dir.path().to_path_buf();
    for i in 0..32 {
        path.push(format!("d{i}"));
        std::fs::create_dir(&path).expect("mkdir");
    }
    std::fs::write(path.join("deep.txt"), "DEEP=found\n").expect("deep");

    let bodies: Vec<String> = collect_chunks(&FilesystemSource::new(dir.path().to_path_buf()))
        .into_iter()
        .map(|c| c.data.to_string())
        .collect();
    assert!(bodies.iter().any(|b| b.contains("DEEP=found")));
}
