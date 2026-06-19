//! Truncated docker tar must not panic validation.

#[cfg(feature = "docker")]
use keyhog_sources::testing::{SourceTestApi, TestApi};
#[cfg(feature = "docker")]
#[test]
fn docker_tar_corrupt_truncated_no_panic() {
    let dir = tempfile::tempdir().expect("tempdir");
    let tar_path = dir.path().join("trunc.tar");
    std::fs::write(&tar_path, b"not-a-complete-tar-archive").expect("write");
    let _ = TestApi.validate_docker_tar_archive(&tar_path);
}

#[cfg(not(feature = "docker"))]
#[test]
fn docker_tar_corrupt_truncated_no_panic() {
    assert!(!cfg!(feature = "docker"));
}
