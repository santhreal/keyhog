//! R5-T archive adversarial: tar.gz with small text member is scanned.

use super::support::collect_chunks;
use flate2::write::GzEncoder;
use flate2::Compression;
use keyhog_sources::FilesystemSource;
use std::io::Write;

#[test]
fn r5t_tar_gz_single_small_member_scanned() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut tar_builder = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_gnu();
    header.set_path("inner.env").expect("path");
    header.set_size(24);
    header.set_cksum();
    tar_builder
        .append(&header, &b"AWS=AKIAQYLPMN5HFIQR7XYA\n"[..])
        .expect("append");
    let tar_bytes = tar_builder.into_inner().expect("tar");
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&tar_bytes).expect("gzip");
    let gz = encoder.finish().expect("finish");
    std::fs::write(dir.path().join("fixture.tar.gz"), gz).expect("write");
    let bodies: Vec<String> = collect_chunks(&FilesystemSource::new(dir.path().to_path_buf()))
        .into_iter()
        .map(|c| c.data.to_string())
        .collect();
    assert!(
        bodies.iter().any(|b| b.contains("AKIAQYLPMN5HFIQR7XYA")),
        "tar.gz member must be scanned; got {bodies:?}"
    );
}
