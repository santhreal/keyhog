//! R5-T archive adversarial: ZIP slip with uppercase DOTDOT blocked.

use super::support::collect_zip_slip_bodies;
use keyhog_sources::FilesystemSource;
use std::fs::File;
use std::io::Write;
use zip::write::SimpleFileOptions;
use zip::ZipWriter;

#[test]
fn r5t_zip_slip_uppercase_dotdot_not_extracted() {
    let dir = tempfile::tempdir().expect("tempdir");
    let zip_path = dir.path().join("upper.zip");
    let file = File::create(&zip_path).expect("create");
    let mut zip = ZipWriter::new(file);
    let opts = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    zip.start_file("..\\..\\secret.env", opts).expect("start");
    zip.write_all(b"LEAK=1\n").expect("write");
    zip.finish().expect("finish");
    let bodies = collect_zip_slip_bodies(
        &FilesystemSource::new(dir.path().to_path_buf()),
        "..\\..\\secret.env",
    );
    assert!(
        !bodies.iter().any(|b| b.contains("LEAK=1")),
        "uppercase dotdot must not extract; got {bodies:?}"
    );
}
