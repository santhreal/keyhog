//! Default ignore rules must skip target/ build artifacts.

use keyhog_core::Source;
use keyhog_sources::FilesystemSource;

#[test]
fn scan_skips_target_directory_by_default() {
    let dir = tempfile::tempdir().expect("tempdir");
    let target = dir.path().join("target").join("debug");
    std::fs::create_dir_all(&target).expect("mkdir");
    std::fs::write(
        target.join("embedded.env"),
        "TOKEN=must-not-scan-target-dir
",
    )
    .expect("write");
    std::fs::write(
        dir.path().join("src.env"),
        "TOKEN=scan-root
",
    )
    .expect("write");

    let bodies: Vec<String> = FilesystemSource::new(dir.path().to_path_buf())
        .chunks()
        .flatten()
        .map(|c| c.data.to_string())
        .collect();
    assert!(bodies.iter().any(|b| b.contains("scan-root")));
    assert!(
        !bodies
            .iter()
            .any(|b| b.contains("must-not-scan-target-dir")),
        "target/ must be ignored by default"
    );
}
