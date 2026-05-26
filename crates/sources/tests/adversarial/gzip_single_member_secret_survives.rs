//! Valid single-member gzip must still surface inner secrets.

use flate2::write::GzEncoder;
use flate2::Compression;
use keyhog_core::Source;
use keyhog_sources::FilesystemSource;
use std::fs::File;
use std::io::Write;

#[test]
fn gzip_single_member_secret_survives() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("cfg.env.gz");
    let file = File::create(&path).expect("create");
    let mut enc = GzEncoder::new(file, Compression::default());
    enc.write_all(b"AWS_SECRET=super-secret-value
").expect("write");
    enc.finish().expect("finish");

    let bodies: Vec<String> = FilesystemSource::new(dir.path().to_path_buf())
        .chunks()
        .flatten()
        .map(|c| c.data.to_string())
        .collect();
    assert!(
        bodies.iter().any(|b| b.contains("super-secret-value")),
        "gzip member must decompress; got {bodies:?}"
    );
}
