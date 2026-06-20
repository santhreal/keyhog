//! R5-T archive adversarial: tar with long name entry does not panic.

use super::support::collect_chunks;
use keyhog_sources::FilesystemSource;

#[test]
fn r5t_tar_longname_entry_no_panic() {
    let dir = tempfile::tempdir().expect("tempdir");
    let long = "a".repeat(120);
    let mut tar_builder = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_gnu();
    header.set_size(3);
    tar_builder
        .append_data(&mut header, format!("{long}.txt"), &b"ok\n"[..])
        .expect("append");
    std::fs::write(
        dir.path().join("long.tar"),
        tar_builder.into_inner().expect("tar"),
    )
    .expect("write");
    let _ = collect_chunks(&FilesystemSource::new(dir.path().to_path_buf()))
        .into_iter()
        .count();
}
