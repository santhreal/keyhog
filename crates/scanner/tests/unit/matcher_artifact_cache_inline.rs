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

/// WHY: cache hits must decode directly from the bounded file buffer; copying
/// every persisted matcher section recreated the startup allocation floor.
#[test]
fn startup_parser_borrows_every_matcher_section_from_one_buffer() {
    let identity = MatcherArtifactIdentity {
        version: MATCHER_ARTIFACT_VERSION,
        binary_digest: "binary".to_owned(),
        binary_version: "version".to_owned(),
        git_hash: "commit".to_owned(),
        target: "target".to_owned(),
        features: "features".to_owned(),
        detector_corpus_digest: "detectors".to_owned(),
        resolved_config_digest: "config".to_owned(),
        pack_generation: "none".to_owned(),
        backend: "Cpu".to_owned(),
        runtime_identity: "none".to_owned(),
        route_matcher_section_version: crate::execution_pack::ROUTE_MATCHER_SECTION_VERSION,
    };
    let literal = br#"{"literal":"section"}"#;
    let regex = br#"{"regex":"section"}"#;
    let suppression = br#"{"suppression":"section"}"#;
    let identity_json = serde_json::to_vec(&identity).expect("serialize identity");
    let content_digest =
        CompiledRouteMatcherSections::content_digest_for(literal, regex, suppression);
    let mut bytes = Vec::new();
    bytes.extend_from_slice(MATCHER_ARTIFACT_MAGIC);
    bytes.extend_from_slice(&MATCHER_ARTIFACT_VERSION.to_le_bytes());
    bytes.extend_from_slice(
        &u32::try_from(identity_json.len())
            .expect("identity length")
            .to_le_bytes(),
    );
    bytes.extend_from_slice(&identity_json);
    bytes.extend_from_slice(&identity.digest());
    bytes.extend_from_slice(&content_digest);
    for section in [literal.as_slice(), regex.as_slice(), suppression.as_slice()] {
        bytes.extend_from_slice(
            &u32::try_from(section.len())
                .expect("section length")
                .to_le_bytes(),
        );
        bytes.extend_from_slice(section);
    }

    let path = std::path::Path::new("borrowed.khm");
    let (_, ranges) =
        parse_matcher_artifact_ranges(path, &bytes, Some(&identity)).expect("parse artifact");
    let loaded = BorrowedMatcherArtifact { bytes, ranges };
    let base = loaded.bytes.as_ptr() as usize;
    let end = base + loaded.bytes.len();
    let (loaded_literal, loaded_regex, loaded_suppression) = loaded.section_bytes();
    for section in [loaded_literal, loaded_regex, loaded_suppression] {
        let address = section.as_ptr() as usize;
        assert!(
            address >= base && address + section.len() <= end,
            "matcher section was not borrowed from the capped artifact buffer"
        );
    }
    assert_eq!(loaded_literal, literal);
    assert_eq!(loaded_regex, regex);
    assert_eq!(loaded_suppression, suppression);

    let owned = loaded.to_owned_sections();
    assert_eq!(owned.literal_index, literal);
    assert_eq!(owned.regex_programs, regex);
    assert_eq!(owned.suppression_policy, suppression);
}
