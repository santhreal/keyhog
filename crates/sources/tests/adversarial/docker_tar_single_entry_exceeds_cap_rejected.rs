//! Docker tar per-entry declared size above cap must be rejected.

#[cfg(feature = "docker")]
use keyhog_sources::skip_counts;
#[cfg(feature = "docker")]
use keyhog_sources::testing::{SourceTestApi, TestApi};
#[cfg(feature = "docker")]
#[test]
fn docker_tar_single_entry_exceeds_cap_rejected() {
    let _guard = TestApi.skip_counter_guard();
    TestApi.reset_skip_counters();
    let dir = tempfile::tempdir().expect("tempdir");
    let tar_path = dir.path().join("huge.tar");
    let file = std::fs::File::create(&tar_path).expect("create tar");
    let mut builder = tar::Builder::new(file);
    let declared = 128 * 1024 * 1024 + 1;
    let mut header = tar::Header::new_gnu();
    header.set_path("huge.bin").expect("set path");
    header.set_size(declared);
    header.set_entry_type(tar::EntryType::Regular);
    header.set_cksum();
    builder.append(&header, b"x".as_slice()).expect("append");
    builder.finish().expect("finish tar");

    let err = TestApi.validate_docker_tar_archive(&tar_path).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("exceeds"),
        "expected per-entry cap rejection, got {msg:?}"
    );
    let counts = skip_counts();
    assert_eq!(
        counts.over_max_size, 1,
        "Docker per-entry cap rejection must be visible as over-max-size telemetry"
    );
    assert_eq!(
        counts.archive_truncated, 0,
        "per-entry cap rejection is not an aggregate archive truncation"
    );
}

#[cfg(not(feature = "docker"))]
#[test]
fn docker_tar_single_entry_exceeds_cap_rejected() {
    assert!(!cfg!(feature = "docker"));
}
