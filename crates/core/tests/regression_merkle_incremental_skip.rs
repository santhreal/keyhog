//! Regression: incremental scan-skip contract of `merkle_index`.
//!
//! The incremental scanner's whole correctness/speed bargain is:
//!   * an UNCHANGED file (same content hash) is recognized and SKIPPED
//!     (`record_*_check_unchanged` returns `true`),
//!   * a single changed byte flips the content hash so the file is
//!     RESCANNED (returns `false`), a freshly injected secret can never be
//!     silently skipped,
//!   * the persisted JSON cache round-trips the EXACT `(mtime, size, BLAKE3)`
//!     tuple, and the racy-clean / spec-hash / schema guards fail closed to a
//!     cold start rather than trust a stale entry.
//!
//! Every assertion is a CONCRETE value (exact bool / count / byte tuple /
//! enum variant + fields), never a shape check. Access is through the crate's
//! doc(hidden) `testing::CoreTestApi` facade plus the type's own `pub`
//! methods and `pub` re-exports (`MerkleLoadStatus`, `compute_spec_hash`).
//! This file is disjoint from `regression_merkle_incremental.rs`: it pins the
//! load-report status variants, the racy-clean drop, the spec-hash gate driven
//! by the real `compute_spec_hash`, and the load-time entry cap.

use keyhog_core::testing::{CoreTestApi, TestApi};
use keyhog_core::{
    compute_spec_hash, DetectorSpec, MerkleIndex, MerkleLoadStatus, PatternSpec, Severity,
};

// ── core skip contract: content-hash authority ────────────────────────────

#[test]
fn unchanged_content_is_skipped_and_changed_byte_forces_rescan() {
    let api = TestApi;
    let idx = api.merkle_empty();
    let path = std::path::PathBuf::from("src/creds.rs");
    let v1 = b"aws_key = AKIAIOSFODNN7EXAMPLE";

    // First sighting is never a skip.
    assert!(
        !api.merkle_record_chunk_at_offset_and_check_unchanged(
            &idx,
            path.clone(),
            0,
            1_000,
            v1.len() as u64,
            v1
        ),
        "first observation must return false (new, not skipped)"
    );
    // Identical content on the next run is SKIPPED.
    assert!(
        api.merkle_record_chunk_at_offset_and_check_unchanged(
            &idx,
            path.clone(),
            0,
            1_000,
            v1.len() as u64,
            v1
        ),
        "unchanged content must return true (skip)"
    );
    // One byte flipped => content hash differs => RESCAN.
    let v2 = b"aws_key = AKIAIOSFODNN7EXAMPLF";
    assert!(
        !api.merkle_record_chunk_at_offset_and_check_unchanged(
            &idx,
            path.clone(),
            0,
            1_000,
            v2.len() as u64,
            v2
        ),
        "a one-byte content change must return false (rescan)"
    );
    // The edited bytes become the new baseline (skipped from now on).
    assert!(
        api.merkle_record_chunk_at_offset_and_check_unchanged(
            &idx,
            path.clone(),
            0,
            1_000,
            v2.len() as u64,
            v2
        ),
        "the edited content becomes the cached baseline"
    );
    assert_eq!(
        api.merkle_len(&idx),
        1,
        "edits update in place: still one row"
    );
}

#[test]
fn distinct_files_never_alias_a_skip() {
    // Adversarial cross-file: seeing file A must NOT make a *different* file B
    // report unchanged. Skip is keyed on (path, content), never on content
    // alone.
    let api = TestApi;
    let idx = api.merkle_empty();
    let a = std::path::PathBuf::from("dir/a.env");
    let b = std::path::PathBuf::from("dir/b.env");
    let ca = b"TOKEN=alpha-alpha-alpha";
    let cb = b"TOKEN=bravo-bravo-bravo";

    assert!(
        !api.merkle_record_chunk_at_offset_and_check_unchanged(&idx, a.clone(), 0, 1, 23, ca),
        "a.env first sighting is new"
    );
    assert!(
        !api.merkle_record_chunk_at_offset_and_check_unchanged(&idx, b.clone(), 0, 1, 23, cb),
        "b.env first sighting is new (A being cached does not alias B)"
    );
    assert_eq!(api.merkle_len(&idx), 2, "two independent paths => two rows");
    // Each re-observes as unchanged only against its OWN content.
    assert!(
        api.merkle_record_chunk_at_offset_and_check_unchanged(&idx, a.clone(), 0, 1, 23, ca),
        "a.env unchanged against its own bytes"
    );
    assert!(
        api.merkle_record_chunk_at_offset_and_check_unchanged(&idx, b.clone(), 0, 1, 23, cb),
        "b.env unchanged against its own bytes"
    );
    // Feeding B's bytes under A's path is a CHANGE for A.
    assert!(
        !api.merkle_record_chunk_at_offset_and_check_unchanged(&idx, a.clone(), 0, 1, 23, cb),
        "swapping in b.env's content under a.env's path is a rescan"
    );
}

#[test]
fn stored_hash_is_the_skip_authority_not_metadata() {
    let api = TestApi;
    let idx = api.merkle_empty();
    let path = std::path::PathBuf::from("racy/config.toml");
    let stored = api.merkle_hash_content(b"key = \"AAAA\"");
    api.merkle_record_with_metadata(&idx, path.clone(), 5, 12, stored);

    // (mtime,size) fast-path says "unchanged"...
    assert!(
        api.merkle_metadata_unchanged(&idx, &path, 5, 12),
        "exact (mtime,size) match => metadata fast-path true"
    );
    // ...yet the authoritative content hash for different bytes is NOT a skip.
    let different = api.merkle_hash_content(b"key = \"BBBB\"");
    assert!(
        !api.merkle_unchanged(&idx, &path, &different),
        "different content hash => not unchanged, even when metadata matched"
    );
    // The originally stored fingerprint is intact.
    assert_eq!(
        api.merkle_lookup(&idx, &path),
        Some((5, 12, stored)),
        "lookup returns the exact stored (mtime,size,hash)"
    );
}

// ── metadata fast-path: exact + u64 boundaries ────────────────────────────

#[test]
fn metadata_fast_path_is_exact_at_u64_boundaries() {
    let api = TestApi;
    let idx = api.merkle_empty();
    let path = std::path::PathBuf::from("big/blob.bin");
    let h = api.merkle_hash_content(b"payload");
    api.merkle_record_with_metadata(&idx, path.clone(), 0, u64::MAX, h);

    assert!(
        api.merkle_metadata_unchanged(&idx, &path, 0, u64::MAX),
        "exact match at (mtime=0, size=u64::MAX) => true"
    );
    assert!(
        !api.merkle_metadata_unchanged(&idx, &path, 1, u64::MAX),
        "mtime off by one => false"
    );
    assert!(
        !api.merkle_metadata_unchanged(&idx, &path, 0, u64::MAX - 1),
        "size off by one => false"
    );
    assert!(
        !api.merkle_metadata_unchanged(&idx, std::path::Path::new("nope.bin"), 0, u64::MAX),
        "unknown path => false"
    );
}

// ── save/load round-trip: exact hash tuple ────────────────────────────────

#[test]
fn cache_roundtrips_the_exact_blake3_hash() {
    let api = TestApi;
    let dir = tempfile::tempdir().unwrap();
    let cache = dir.path().join("merkle.idx");

    let content = b"database_url=postgres://u:p@h/db";
    let hash = api.merkle_hash_content(content);
    // Confirm the stored hash IS the BLAKE3 of the bytes.
    assert_eq!(
        hash,
        *blake3::hash(content).as_bytes(),
        "hash_content must be BLAKE3 of the exact bytes"
    );

    let idx = api.merkle_empty();
    api.merkle_record_with_metadata(
        &idx,
        std::path::PathBuf::from("conf/app.ini"),
        7_777,
        content.len() as u64,
        hash,
    );
    api.merkle_save(&idx, &cache).expect("save must succeed");

    let loaded = api.merkle_load(&cache);
    assert_eq!(
        api.merkle_len(&loaded),
        1,
        "one entry survives the round-trip"
    );
    assert_eq!(
        api.merkle_lookup(&loaded, std::path::Path::new("conf/app.ini")),
        Some((7_777, content.len() as u64, hash)),
        "the loaded tuple is byte-identical to what was saved"
    );
    // And the round-tripped hash still recognizes identical content as a skip.
    assert!(
        api.merkle_unchanged(&loaded, std::path::Path::new("conf/app.ini"), &hash),
        "round-tripped hash still classifies identical content as unchanged"
    );
}

#[test]
fn roundtrip_preserves_every_entry_exactly() {
    let api = TestApi;
    let dir = tempfile::tempdir().unwrap();
    let cache = dir.path().join("many.idx");

    let rows: [(&str, u64, u64, &[u8]); 5] = [
        ("a.rs", 11, 5, b"alpha"),
        ("b/c.rs", 22, 6, b"bravos"),
        ("d/e/f.rs", 33, 7, b"charlie"),
        ("g.env", 44, 3, b"KEY"),
        ("h.toml", 55, 4, b"x=42"),
    ];
    let idx = api.merkle_empty();
    let mut expected = Vec::new();
    for (p, mtime, size, bytes) in rows {
        let h = api.merkle_hash_content(bytes);
        api.merkle_record_with_metadata(&idx, std::path::PathBuf::from(p), mtime, size, h);
        expected.push((p, (mtime, size, h)));
    }
    assert_eq!(api.merkle_len(&idx), 5, "five entries before save");
    api.merkle_save(&idx, &cache).expect("save must succeed");

    let loaded = api.merkle_load(&cache);
    assert_eq!(api.merkle_len(&loaded), 5, "all five entries survive");
    for (p, tuple) in expected {
        assert_eq!(
            api.merkle_lookup(&loaded, std::path::Path::new(p)),
            Some(tuple),
            "entry {p} round-trips byte-identically"
        );
    }
    assert_eq!(
        api.merkle_lookup(&loaded, std::path::Path::new("never.rs")),
        None,
        "a path never stored is absent after load"
    );
}

// ── racy-clean guard: fail closed on future-mtime entries ─────────────────

#[test]
fn racy_clean_guard_drops_future_mtime_entries_on_load() {
    // git's "racy index" guard: an entry whose file mtime is at/after the
    // moment we wrote the index cannot be trusted by (mtime,size) alone (a
    // size-preserving edit in that window would be invisible), so it is dropped
    // and re-scanned. A tiny mtime is safely below the write time and survives.
    let api = TestApi;
    let dir = tempfile::tempdir().unwrap();
    let cache = dir.path().join("racy.idx");

    let idx = api.merkle_empty();
    let old = api.merkle_hash_content(b"old-and-trusted");
    let fresh = api.merkle_hash_content(b"racy-just-written");
    // mtime 1ns: far below now => trusted. mtime u64::MAX: after the write =>
    // racy => dropped on load.
    api.merkle_record_with_metadata(&idx, std::path::PathBuf::from("old.rs"), 1, 15, old);
    api.merkle_record_with_metadata(
        &idx,
        std::path::PathBuf::from("fresh.rs"),
        u64::MAX,
        17,
        fresh,
    );
    assert_eq!(api.merkle_len(&idx), 2, "both rows present in memory");
    api.merkle_save(&idx, &cache).expect("save must succeed");

    let report = api.merkle_load_report(&cache);
    match report.status() {
        MerkleLoadStatus::Loaded { entries, .. } => {
            assert_eq!(*entries, 1, "exactly one non-racy entry is retained");
        }
        other => panic!("expected Loaded status, got {other:?}"),
    }
    let loaded = report.into_index();
    assert_eq!(
        api.merkle_lookup(&loaded, std::path::Path::new("old.rs")),
        Some((1, 15, old)),
        "the trusted (small-mtime) entry survives exactly"
    );
    assert_eq!(
        api.merkle_lookup(&loaded, std::path::Path::new("fresh.rs")),
        None,
        "the racy (future-mtime) entry is dropped and will be re-scanned"
    );
}

// ── load-report status variants: fail closed, cold start ──────────────────

#[test]
fn load_missing_file_reports_missing_status() {
    let api = TestApi;
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("absent.idx");
    let report = api.merkle_load_report(&missing);
    match report.status() {
        MerkleLoadStatus::Missing { path } => {
            assert_eq!(
                path.as_path(),
                missing.as_path(),
                "Missing carries the probed path"
            );
        }
        other => panic!("expected Missing, got {other:?}"),
    }
    assert_eq!(
        api.merkle_len(&report.into_index()),
        0,
        "missing => 0 entries"
    );
}

#[test]
fn corrupt_json_reports_parse_failed_and_cold_starts() {
    let api = TestApi;
    let dir = tempfile::tempdir().unwrap();
    let cache = dir.path().join("corrupt.idx");
    std::fs::write(&cache, b"{ this is not valid json ]]").unwrap();

    let report = api.merkle_load_report(&cache);
    assert!(
        matches!(report.status(), MerkleLoadStatus::ParseFailed { .. }),
        "unparseable JSON must yield ParseFailed, got {:?}",
        report.status()
    );
    assert_eq!(
        api.merkle_len(&report.into_index()),
        0,
        "parse failure cold-starts to an empty index"
    );
}

#[test]
fn wrong_schema_version_reports_schema_mismatch() {
    let api = TestApi;
    let dir = tempfile::tempdir().unwrap();
    let cache = dir.path().join("v99.idx");
    // Valid JSON, incompatible schema version.
    std::fs::write(&cache, br#"{"version":99,"entries":[]}"#).unwrap();

    let report = api.merkle_load_report(&cache);
    match report.status() {
        MerkleLoadStatus::SchemaMismatch {
            version, expected, ..
        } => {
            assert_eq!(*version, 99, "the found version is reported verbatim");
            assert_eq!(*expected, 4, "the current binary requires schema v4");
        }
        other => panic!("expected SchemaMismatch, got {other:?}"),
    }
    assert_eq!(
        api.merkle_len(&report.into_index()),
        0,
        "schema mismatch => cold start"
    );
}

#[test]
fn invalid_entry_hash_reports_invalid_entry_hash() {
    let api = TestApi;
    let dir = tempfile::tempdir().unwrap();
    let cache = dir.path().join("badhash.idx");
    // Correct schema, but one entry has a non-hex digest.
    std::fs::write(
        &cache,
        br#"{"version":4,"written_at_ns":0,"entries":[{"path":"bad/x.rs","mtime_ns":1,"size":10,"hash":"nothex"}]}"#,
    )
    .unwrap();

    let report = api.merkle_load_report(&cache);
    match report.status() {
        MerkleLoadStatus::InvalidEntryHash {
            entry_path, hash, ..
        } => {
            assert_eq!(
                entry_path.as_str(),
                "bad/x.rs",
                "the offending path is reported"
            );
            assert_eq!(
                hash.as_str(),
                "nothex",
                "the invalid digest is reported verbatim"
            );
        }
        other => panic!("expected InvalidEntryHash, got {other:?}"),
    }
    assert_eq!(
        api.merkle_len(&report.into_index()),
        0,
        "an invalid persisted hash cold-starts the whole cache"
    );
}

// ── spec-hash gate driven by the real compute_spec_hash ───────────────────

fn sample_detector(severity: Severity) -> DetectorSpec {
    DetectorSpec {
        kind: Default::default(),
        entropy_floor: Vec::new(),
        tests: Vec::new(),
        id: "sample-detector".into(),
        name: "sample".into(),
        service: "sample".into(),
        severity,
        keywords: vec!["secret".into()],
        min_confidence: None,
        patterns: vec![PatternSpec {
            regex: "[A-Z0-9]{32}".into(),
            ..Default::default()
        }],
        companions: vec![],
        verify: None,
        // Fill any newer optional fields (allowlist_paths/allowlist_values/
        // entropy_high, …) with their defaults so this exhaustive literal does
        // not break every time the spec grows a field. Explicit fields above
        // still win; only unlisted ones default.
        ..Default::default()
    }
}

#[test]
fn compute_spec_hash_is_deterministic_and_severity_sensitive() {
    let base = sample_detector(Severity::Medium);
    // Same detector set hashes identically every call.
    assert_eq!(
        compute_spec_hash(std::slice::from_ref(&base)),
        compute_spec_hash(std::slice::from_ref(&base)),
        "identical detector sets must hash identically"
    );
    // A severity change perturbs the digest so the cache invalidates.
    let hotter = sample_detector(Severity::High);
    assert_ne!(
        compute_spec_hash(std::slice::from_ref(&base)),
        compute_spec_hash(std::slice::from_ref(&hotter)),
        "changing a detector's severity must change the spec hash"
    );
    // The digest is BLAKE3-width.
    assert_eq!(
        compute_spec_hash(std::slice::from_ref(&base)).len(),
        32,
        "spec hash is a 32-byte BLAKE3 digest"
    );
}

#[test]
fn spec_gate_trusts_matching_hash_and_invalidates_on_change() {
    let api = TestApi;
    let dir = tempfile::tempdir().unwrap();
    let cache = dir.path().join("spec.idx");

    let spec_before = compute_spec_hash(&[sample_detector(Severity::Medium)]);
    let spec_after = compute_spec_hash(&[sample_detector(Severity::High)]);
    assert_ne!(
        spec_before, spec_after,
        "the two specs differ (precondition)"
    );

    let idx = api.merkle_empty();
    let h = api.merkle_hash_content(b"gated-content");
    api.merkle_record_with_metadata(&idx, std::path::PathBuf::from("g.rs"), 100, 13, h);
    idx.save_with_spec(&cache, &spec_before)
        .expect("spec-tagged save must succeed");

    // Same detector spec => cache trusted, entry present and exact.
    let same = MerkleIndex::load_with_spec_report(&cache, &spec_before);
    match same.status() {
        MerkleLoadStatus::Loaded { entries, .. } => {
            assert_eq!(*entries, 1, "matching spec keeps the one entry")
        }
        other => panic!("expected Loaded, got {other:?}"),
    }
    assert_eq!(
        api.merkle_lookup(&same.into_index(), std::path::Path::new("g.rs")),
        Some((100, 13, h)),
        "matching spec preserves the exact tuple"
    );

    // Detector spec changed => whole cache invalidated.
    let changed = MerkleIndex::load_with_spec_report(&cache, &spec_after);
    assert!(
        matches!(changed.status(), MerkleLoadStatus::SpecChanged { .. }),
        "a changed detector spec must report SpecChanged, got {:?}",
        changed.status()
    );
    assert_eq!(
        api.merkle_len(&changed.into_index()),
        0,
        "spec change cold-starts to an empty index"
    );
}

// ── load honors the entry cap ─────────────────────────────────────────────

#[test]
fn load_with_max_entries_caps_loaded_rows() {
    let api = TestApi;
    let dir = tempfile::tempdir().unwrap();
    let cache = dir.path().join("cap.idx");

    // Persist five small-mtime (non-racy) entries.
    let idx = api.merkle_empty();
    for i in 0..5u64 {
        let h = api.merkle_hash_content(format!("row-{i}").as_bytes());
        api.merkle_record_with_metadata(
            &idx,
            std::path::PathBuf::from(format!("p{i}.rs")),
            i + 1,
            4,
            h,
        );
    }
    api.merkle_save(&idx, &cache).expect("save must succeed");
    assert_eq!(
        api.merkle_len(&api.merkle_load(&cache)),
        5,
        "all five persist uncapped"
    );

    // Loading with a cap of 3 retains exactly three rows (insert stops at cap).
    let capped = api.merkle_load_with_max_entries(&cache, 3);
    assert_eq!(
        api.merkle_len(&capped),
        3,
        "load honors the entry cap: exactly three rows retained"
    );
    assert_eq!(
        api.merkle_max_entries(&capped),
        3,
        "the cap is recorded on the loaded index"
    );
}
