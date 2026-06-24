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

#[cfg(feature = "docker")]
#[test]
fn docker_layer_over_cap_regular_entry_is_reported_without_dropping_safe_siblings() {
    let _guard = TestApi.skip_counter_guard();
    TestApi.reset_skip_counters();
    let dir = tempfile::tempdir().expect("tempdir");
    let tar_path = dir.path().join("layer.tar");
    let file = std::fs::File::create(&tar_path).expect("create tar");
    let mut builder = tar::Builder::new(file);

    let mut huge_header = tar::Header::new_gnu();
    huge_header.set_path("huge.bin").expect("set huge path");
    huge_header.set_size(5);
    huge_header.set_entry_type(tar::EntryType::Regular);
    huge_header.set_cksum();
    builder
        .append(&huge_header, b"12345".as_slice())
        .expect("append huge entry");

    let mut safe_header = tar::Header::new_gnu();
    safe_header.set_path("safe.txt").expect("set safe path");
    safe_header.set_size(3);
    safe_header.set_entry_type(tar::EntryType::Regular);
    safe_header.set_cksum();
    builder
        .append(&safe_header, b"ok\n".as_slice())
        .expect("append safe entry");
    builder.finish().expect("finish tar");

    let unpacked = dir.path().join("unpacked");
    std::fs::create_dir(&unpacked).expect("mkdir unpacked");
    let errors = TestApi
        .unpack_docker_layer_archive_with_entry_cap(&tar_path, &unpacked, 4)
        .expect("over-cap regular entries must not abort the whole layer");

    assert!(
        !unpacked.join("huge.bin").exists(),
        "over-cap Docker layer entry must not be extracted"
    );
    assert_eq!(
        std::fs::read_to_string(unpacked.join("safe.txt")).expect("safe sibling extracted"),
        "ok\n",
        "safe sibling after an over-cap entry must still be scanned"
    );
    assert_eq!(errors.len(), 1, "expected one visible skip error");
    let msg = errors[0].to_string();
    assert!(
        msg.contains("huge.bin") && msg.contains("not scanned"),
        "over-cap skip must be operator-visible, got {msg:?}"
    );

    let counts = skip_counts();
    assert_eq!(
        counts.over_max_size, 1,
        "Docker per-entry cap skip must increment over-max-size telemetry"
    );
    assert_eq!(
        counts.archive_truncated, 0,
        "per-entry skip is not an aggregate archive truncation"
    );
}

#[cfg(feature = "docker")]
#[test]
fn docker_image_archive_entries_use_total_cap_not_layer_file_cap() {
    let _guard = TestApi.skip_counter_guard();
    TestApi.reset_skip_counters();
    let dir = tempfile::tempdir().expect("tempdir");
    let tar_path = dir.path().join("image.tar");
    let file = std::fs::File::create(&tar_path).expect("create tar");
    let mut builder = tar::Builder::new(file);

    let mut layer_header = tar::Header::new_gnu();
    layer_header
        .set_path("layer.tar")
        .expect("set layer archive path");
    layer_header.set_size(5);
    layer_header.set_entry_type(tar::EntryType::Regular);
    layer_header.set_cksum();
    builder
        .append(&layer_header, b"12345".as_slice())
        .expect("append outer layer archive entry");
    builder.finish().expect("finish tar");

    let unpacked = dir.path().join("image");
    std::fs::create_dir(&unpacked).expect("mkdir image");
    let errors = TestApi
        .unpack_docker_image_archive_with_entry_cap(&tar_path, &unpacked, 4)
        .expect("outer Docker image archive must not apply the inner layer file cap");

    assert!(
        errors.is_empty(),
        "outer archive member above the per-file scan cap must not emit a skipped-file error: {errors:?}"
    );
    assert_eq!(
        std::fs::read(unpacked.join("layer.tar")).expect("outer layer member extracted"),
        b"12345",
        "Docker image archive members are bounded by the aggregate image cap so layers can be scanned internally"
    );
    let counts = skip_counts();
    assert_eq!(
        counts.over_max_size, 0,
        "outer layer archive members must not be counted as skipped layer files"
    );
}

#[cfg(not(feature = "docker"))]
#[test]
fn docker_tar_single_entry_exceeds_cap_rejected() {
    assert!(!cfg!(feature = "docker"));
}
