//! Zip entries with `../` path components must not surface extracted secrets.

use super::support::collect_zip_slip_bodies;
use keyhog_sources::FilesystemSource;
use std::fs::File;
use std::io::Write;
use zip::write::SimpleFileOptions;
use zip::ZipWriter;

#[test]
fn zip_slip_dotdot_entry_not_extracted() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("outside.txt"), "OUTSIDE=ok\n").expect("outside");

    let file = File::create(dir.path().join("slip.zip")).expect("create");
    let mut zip = ZipWriter::new(file);
    let opts = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    zip.start_file("../escape.env", opts).expect("start slip");
    zip.write_all(b"SLIP=AKIAQYLPMN5HFIQR7XYA\n")
        .expect("write");
    zip.start_file("safe.txt", opts).expect("start safe");
    zip.write_all(b"SAFE=1\n").expect("write safe");
    zip.finish().expect("finish");

    let bodies = collect_zip_slip_bodies(
        &FilesystemSource::new(dir.path().to_path_buf()),
        "../escape.env",
    );

    assert!(
        bodies.iter().any(|b| b.contains("OUTSIDE=ok")),
        "filesystem walk must continue when archive extraction is hostile"
    );
    assert!(
        !bodies.iter().any(|b| b.contains("SLIP=AKIA")),
        "path traversal entry must not surface; got {bodies:?}"
    );
}
