//! Docker tar archives whose cumulative declared size exceeds the aggregate cap
//! must be rejected before unpack (zip-bomb defense).

#[cfg(feature = "docker")]
use keyhog_sources::skip_counts;
#[cfg(feature = "docker")]
use keyhog_sources::testing::{SourceTestApi, TestApi};
#[cfg(feature = "docker")]
#[test]
fn docker_tar_aggregate_cap_enforced() {
    let _guard = TestApi.skip_counter_guard();
    TestApi.reset_skip_counters();
    let dir = tempfile::tempdir().expect("tempdir");
    let tar_path = dir.path().join("aggregate_bomb.tar");
    let file = std::fs::File::create(&tar_path).expect("create tar");
    let mut builder = tar::Builder::new(file);

    // Three 400-byte entries exceed a 1000-byte cumulative test cap.
    for i in 0..3 {
        let payload = vec![b'Z'; 400];
        let mut header = tar::Header::new_gnu();
        header.set_path(format!("part{i}.bin")).expect("set path");
        header.set_size(400);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_cksum();
        builder.append(&header, payload.as_slice()).expect("append");
    }
    builder.finish().expect("finish tar");

    let err = TestApi
        .validate_docker_tar_archive_with_total_cap(&tar_path, 1_000)
        .unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("cumulative size exceeds") && msg.contains("zip-bomb"),
        "expected aggregate cap rejection, got {msg:?}"
    );
    let counts = skip_counts();
    assert_eq!(
        counts.archive_truncated, 1,
        "Docker aggregate cap rejection must be visible as archive-truncated telemetry"
    );
    assert_eq!(
        counts.over_max_size, 0,
        "aggregate cap rejection is not a single-entry over-max-size skip"
    );
}

#[cfg(not(feature = "docker"))]
#[test]
fn docker_tar_aggregate_cap_requires_docker_feature() {
    assert!(!cfg!(feature = "docker"));
}
