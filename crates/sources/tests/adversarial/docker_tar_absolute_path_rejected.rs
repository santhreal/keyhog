//! Docker tar absolute paths must be rejected.

#[cfg(feature = "docker")]
use keyhog_sources::testing::{SourceTestApi, TestApi};
#[cfg(feature = "docker")]
#[test]
fn docker_tar_absolute_path_rejected() {
    let dir = tempfile::tempdir().expect("tempdir");
    let tar_path = dir.path().join("hostile.tar");
    let file = std::fs::File::create(&tar_path).expect("create tar");
    let mut builder = tar::Builder::new(file);
    let payload = b"SECRET=1\n";
    let mut header = tar::Header::new_gnu();
    header.set_path("benign.bin").expect("set benign path");
    patch_header_path(&mut header, "/etc/passwd");
    header.set_size(payload.len() as u64);
    header.set_entry_type(tar::EntryType::Regular);
    header.set_cksum();
    builder.append(&header, payload.as_slice()).expect("append");
    builder.finish().expect("finish tar");

    let err = TestApi.validate_docker_tar_archive(&tar_path).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("unsafe path"),
        "expected tar rejection, got {msg:?}"
    );
}

#[cfg(feature = "docker")]
fn patch_header_path(header: &mut tar::Header, evil: &str) {
    let raw = header.as_mut_bytes();
    raw[..100].fill(0);
    let bytes = evil.as_bytes();
    raw[..bytes.len()].copy_from_slice(bytes);
}

#[cfg(not(feature = "docker"))]
#[test]
fn docker_tar_absolute_path_rejected() {
    assert!(!cfg!(feature = "docker"));
}
