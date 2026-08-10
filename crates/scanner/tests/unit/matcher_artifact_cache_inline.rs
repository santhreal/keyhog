use super::*;

/// WHY: hostile section lengths must fail before allocating the serialized artifact.
#[test]
fn serialized_size_bound_rejects_overflow_and_one_byte_over_cap() {
    const ENVELOPE_BYTES: usize = 8 + 4 + 64 + 12;
    let exact_payload =
        usize::try_from(MATCHER_ARTIFACT_FILE_BYTES).expect("cap fits usize") - ENVELOPE_BYTES;
    assert_eq!(
        checked_matcher_artifact_len(exact_payload, 0, 0, 0).expect("exact cap"),
        usize::try_from(MATCHER_ARTIFACT_FILE_BYTES).expect("cap fits usize")
    );
    assert!(checked_matcher_artifact_len(exact_payload + 1, 0, 0, 0)
        .expect_err("one byte over cap")
        .contains("would exceed"));
    assert!(checked_matcher_artifact_len(usize::MAX, 1, 0, 0)
        .expect_err("length overflow")
        .contains("size overflow"));
}

/// WHY: a sparse hostile file must be rejected from metadata without a cap-sized read allocation.
#[test]
fn oversized_sparse_artifact_is_rejected_before_read() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("oversized.khm");
    let file = std::fs::File::create(&path).expect("create sparse artifact");
    file.set_len(MATCHER_ARTIFACT_FILE_BYTES + 1)
        .expect("extend sparse artifact");
    let error = read_matcher_artifact_bytes(&path).expect_err("oversized artifact");
    assert!(error.contains("exceeds") && error.contains("byte cap"));
}

/// WHY: a short write must never publish a cache entry under an authenticated filename.
#[test]
fn atomic_writer_rejects_length_mismatch_before_publish() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("short.khm");
    let error =
        atomic_write(&path, 2, |tmp| tmp.write_all(b"x")).expect_err("short artifact write");
    assert!(error.to_string().contains("produced 1 bytes, expected 2"));
    assert!(!path.exists());
}

/// WHY: adversarial cache-directory cardinality must not make eviction retain an unbounded index.
#[test]
fn eviction_bounds_retained_artifacts_and_ignores_other_files() {
    let dir = tempfile::tempdir().expect("tempdir");
    let unrelated = dir.path().join("keep.txt");
    std::fs::write(&unrelated, b"keep").expect("write unrelated file");
    for index in 0..(MATCHER_ARTIFACT_MAX_ENTRIES * 8) {
        std::fs::write(dir.path().join(format!("artifact-{index:03}.khm")), b"x")
            .expect("write cache entry");
    }

    evict_old_matcher_artifacts(dir.path());

    let retained = std::fs::read_dir(dir.path())
        .expect("read cache dir")
        .flatten()
        .filter(|entry| entry.path().extension().and_then(|ext| ext.to_str()) == Some("khm"))
        .count();
    assert_eq!(retained, MATCHER_ARTIFACT_MAX_ENTRIES);
    assert!(unrelated.exists());
}
