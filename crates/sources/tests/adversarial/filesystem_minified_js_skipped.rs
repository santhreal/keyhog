//! Minified bundle filenames must be excluded from scanning.

use keyhog_core::Source;
use keyhog_sources::FilesystemSource;

#[test]
fn filesystem_minified_js_skipped() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        dir.path().join("app.min.js"),
        "const TOKEN='ghp_shouldNotScanMinifiedBundle';",
    )
    .expect("write");
    std::fs::write(
        dir.path().join("real.env"),
        "TOKEN=scan-me
",
    )
    .expect("write");

    let bodies: Vec<String> = FilesystemSource::new(dir.path().to_path_buf())
        .chunks()
        .flatten()
        .map(|c| c.data.to_string())
        .collect();
    assert!(
        bodies.iter().any(|b| b.contains("scan-me")),
        "non-minified file must scan"
    );
    assert!(
        !bodies
            .iter()
            .any(|b| b.contains("ghp_shouldNotScanMinifiedBundle")),
        "minified bundle must be skipped"
    );
}
