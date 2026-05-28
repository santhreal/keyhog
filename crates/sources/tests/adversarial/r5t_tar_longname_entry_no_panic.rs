//! R5-T archive adversarial: tar with long name entry does not panic.

use keyhog_core::Source;
use keyhog_sources::FilesystemSource;

#[test]
fn r5t_tar_longname_entry_no_panic() {
    let dir = tempfile::tempdir().expect("tempdir");
    let long = "a".repeat(120);
    let mut tar_builder = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_gnu();
    header.set_path(format!("{long}.txt")).expect("path");
    header.set_size(4);
    header.set_cksum();
    tar_builder.append(&header, &b"ok\n"[..]).expect("append");
    std::fs::write(dir.path().join("long.tar"), tar_builder.into_inner().expect("tar")).expect("write");
    let _ = FilesystemSource::new(dir.path().to_path_buf()).chunks().flatten().count();
}
