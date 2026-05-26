//! Empty jar archive must not panic directory scan.

use keyhog_core::Source;
use keyhog_sources::FilesystemSource;
use std::fs::File;
use zip::ZipWriter;

#[test]
fn empty_jar_does_not_panic() {
    let dir = tempfile::tempdir().expect("tempdir");
    let file = File::create(dir.path().join("empty.jar")).expect("create");
    ZipWriter::new(file).finish().expect("finish");
    std::fs::write(dir.path().join("side.txt"), "SIDE=ok
").expect("write");

    let bodies: Vec<String> = FilesystemSource::new(dir.path().to_path_buf())
        .chunks()
        .flatten()
        .map(|c| c.data.to_string())
        .collect();
    assert!(bodies.iter().any(|b| b.contains("SIDE=ok")));
}
