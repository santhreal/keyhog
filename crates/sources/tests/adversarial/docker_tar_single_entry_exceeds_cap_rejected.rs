//! Docker tar per-entry declared size above cap must be rejected.

#[cfg(feature = "docker")]
use keyhog_sources::skip_counts;
#[cfg(feature = "docker")]
use keyhog_sources::testing::{SourceTestApi, TestApi};
#[cfg(feature = "docker")]
fn write_layer_tar(path: &std::path::Path, entries: &[(&str, &[u8])]) {
    let file = std::fs::File::create(path).expect("create tar");
    let mut builder = tar::Builder::new(file);
    for (name, bytes) in entries {
        let mut header = tar::Header::new_gnu();
        header.set_path(name).expect("set entry path");
        header.set_size(bytes.len() as u64);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_cksum();
        builder
            .append(&header, *bytes)
            .expect("append layer entry");
    }
    builder.finish().expect("finish tar");
}

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
        msg.contains("huge.bin")
            && msg.contains("uncompressed size 134217729")
            && msg.contains("per-file cap 134217728")
            && msg.contains("entry was not scanned"),
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
/// A single entry above the per-file cap is skipped without allocation or
/// extraction, while an in-budget sibling is still extracted.
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
        .unpack_docker_layer_archive_with_caps(&tar_path, &unpacked, 4, 9)
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
        msg.contains("huge.bin")
            && msg.contains("uncompressed size 5")
            && msg.contains("per-file cap 4")
            && msg.contains("entry was not scanned"),
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
/// Boundary contract: the inner-layer file cap is inclusive. Only entries
/// strictly larger than the configured cap are skipped.
fn docker_layer_regular_entry_exactly_at_cap_is_extracted() {
    let _guard = TestApi.skip_counter_guard();
    TestApi.reset_skip_counters();
    let dir = tempfile::tempdir().expect("tempdir");
    let tar_path = dir.path().join("layer.tar");
    let file = std::fs::File::create(&tar_path).expect("create tar");
    let mut builder = tar::Builder::new(file);

    let mut header = tar::Header::new_gnu();
    header.set_path("at-cap.txt").expect("set path");
    header.set_size(4);
    header.set_entry_type(tar::EntryType::Regular);
    header.set_cksum();
    builder
        .append(&header, b"1234".as_slice())
        .expect("append exact-cap entry");
    builder.finish().expect("finish tar");

    let unpacked = dir.path().join("unpacked");
    std::fs::create_dir(&unpacked).expect("mkdir unpacked");
    let errors = TestApi
        .unpack_docker_layer_archive_with_entry_cap(&tar_path, &unpacked, 4)
        .expect("an entry exactly at the cap must be accepted");

    assert!(errors.is_empty(), "exact-cap entry emitted errors: {errors:?}");
    assert_eq!(
        std::fs::read(unpacked.join("at-cap.txt")).expect("exact-cap entry extracted"),
        b"1234"
    );
    assert_eq!(
        skip_counts().over_max_size,
        0,
        "an exact-cap entry must not increment skip telemetry"
    );
}

#[cfg(feature = "docker")]
#[test]
/// Aggregate accounting includes oversized entries even though they are never
/// allocated or extracted, so multiple skipped entries cannot bypass the cap.
fn docker_layer_skipped_entries_still_trip_aggregate_cap() {
    let _guard = TestApi.skip_counter_guard();
    TestApi.reset_skip_counters();
    let dir = tempfile::tempdir().expect("tempdir");
    let tar_path = dir.path().join("layer.tar");
    write_layer_tar(
        &tar_path,
        &[("first.bin", b"12345"), ("second.bin", b"67890")],
    );

    let unpacked = dir.path().join("unpacked");
    std::fs::create_dir(&unpacked).expect("mkdir unpacked");
    let err = TestApi
        .unpack_docker_layer_archive_with_caps(&tar_path, &unpacked, 4, 9)
        .expect_err("two skipped five-byte entries must exceed the nine-byte aggregate cap");

    let msg = err.to_string();
    assert!(
        msg.contains("cumulative size exceeds 9 bytes") && msg.contains("second.bin"),
        "aggregate refusal must name the cap and crossing entry, got {msg:?}"
    );
    assert!(
        !unpacked.join("first.bin").exists() && !unpacked.join("second.bin").exists(),
        "preflight rejection must not extract oversized entries"
    );
    assert_eq!(
        skip_counts().archive_truncated,
        1,
        "aggregate refusal must increment archive-truncated telemetry"
    );
}

#[cfg(feature = "docker")]
#[test]
/// The aggregate cap is inclusive: a layer whose declared regular-entry bytes
/// equal the total cap is accepted, while its over-file-cap member stays skipped.
fn docker_layer_exactly_at_aggregate_cap_is_accepted() {
    let _guard = TestApi.skip_counter_guard();
    TestApi.reset_skip_counters();
    let dir = tempfile::tempdir().expect("tempdir");
    let tar_path = dir.path().join("layer.tar");
    write_layer_tar(
        &tar_path,
        &[("safe.txt", b"1234"), ("oversized.bin", b"56789")],
    );

    let unpacked = dir.path().join("unpacked");
    std::fs::create_dir(&unpacked).expect("mkdir unpacked");
    let errors = TestApi
        .unpack_docker_layer_archive_with_caps(&tar_path, &unpacked, 4, 9)
        .expect("declared bytes exactly at the aggregate cap must be accepted");

    assert_eq!(errors.len(), 1, "only the per-file skip must be reported");
    assert_eq!(
        std::fs::read(unpacked.join("safe.txt")).expect("safe entry extracted"),
        b"1234"
    );
    assert!(
        !unpacked.join("oversized.bin").exists(),
        "over-file-cap entry must remain unextracted"
    );
    let counts = skip_counts();
    assert_eq!(counts.archive_truncated, 0);
    assert_eq!(counts.over_max_size, 1);
}

#[cfg(feature = "docker")]
#[test]
/// Positive control: an archive below both budgets extracts every regular
/// entry and emits no skip or truncation telemetry.
fn docker_layer_under_both_caps_extracts_every_entry() {
    let _guard = TestApi.skip_counter_guard();
    TestApi.reset_skip_counters();
    let dir = tempfile::tempdir().expect("tempdir");
    let tar_path = dir.path().join("layer.tar");
    write_layer_tar(&tar_path, &[("one.txt", b"123"), ("two.txt", b"456")]);

    let unpacked = dir.path().join("unpacked");
    std::fs::create_dir(&unpacked).expect("mkdir unpacked");
    let errors = TestApi
        .unpack_docker_layer_archive_with_caps(&tar_path, &unpacked, 4, 7)
        .expect("archive below both caps must be extracted");

    assert!(errors.is_empty(), "in-budget archive emitted errors: {errors:?}");
    assert_eq!(std::fs::read(unpacked.join("one.txt")).unwrap(), b"123");
    assert_eq!(std::fs::read(unpacked.join("two.txt")).unwrap(), b"456");
    let counts = skip_counts();
    assert_eq!(counts.archive_truncated, 0);
    assert_eq!(counts.over_max_size, 0);
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
