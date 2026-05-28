//! Docker tar symlink entries must be rejected.

#[cfg(feature = "docker")]
#[test]
fn docker_tar_symlink_entry_rejected() {
    let dir = tempfile::tempdir().expect("tempdir");
    let tar_path = dir.path().join("hostile.tar");
    let file = std::fs::File::create(&tar_path).expect("create tar");
    let mut builder = tar::Builder::new(file);
    let mut header = tar::Header::new_gnu();
    header.set_path("link").expect("set path");
    header.set_entry_type(tar::EntryType::Symlink);
    header.set_link_name("/etc/passwd").expect("link");
    header.set_size(0);
    header.set_cksum();
    builder.append(&header, &[] as &[u8]).expect("append");
    builder.finish().expect("finish tar");

    let err = keyhog_sources::testing::validate_docker_tar_archive(&tar_path).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("forbidden link"),
        "expected tar rejection, got {msg:?}"
    );
}

#[cfg(not(feature = "docker"))]
#[test]
fn docker_tar_symlink_entry_rejected() {
    assert!(!cfg!(feature = "docker"));
}
