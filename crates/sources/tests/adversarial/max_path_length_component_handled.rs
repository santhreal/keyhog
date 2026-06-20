//! Very long path components must not panic the walker.

use super::support::collect_chunks;
use keyhog_sources::FilesystemSource;

#[test]
fn max_path_length_component_handled() {
    let dir = tempfile::tempdir().expect("tempdir");
    let long_name = "a".repeat(240);
    std::fs::write(dir.path().join(format!("{long_name}.txt")), "LONGNAME=1\n").expect("long");
    std::fs::write(dir.path().join("short.txt"), "SHORT=ok\n").expect("short");

    let bodies: Vec<String> = collect_chunks(&FilesystemSource::new(dir.path().to_path_buf()))
        .into_iter()
        .map(|c| c.data.to_string())
        .collect();

    assert!(
        bodies.iter().any(|b| b.contains("SHORT=ok")),
        "walker must survive long filename entries"
    );
}
