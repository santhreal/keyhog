//! Regression: pin the SEMANTICS of the detector-spec hash and its role as the
//! merkle-cache invalidation key.
//!
//! `compute_spec_hash` is the single BLAKE3 digest over the canonical detector
//! set. The incremental merkle cache stores it alongside the entries so a later
//! scan can prove the detector corpus is unchanged before trusting a "skip this
//! file" decision. If the digest ever stopped changing when a detector changed
//! (Law 10: a silent stale-cache skip would miss a freshly reachable secret
//! forever) or stopped being order-invariant (spurious full re-scans), that is a
//! recall/perf regression. These tests assert EXACT equality/inequality of the
//! 32-byte digest and EXACT cold-start `MerkleLoadStatus` variants, never
//! shapes.
//!
//! Distinct from `regression_merkle_incremental*` (which pin the record/skip hot
//! path): this file pins spec-hash identity and the spec-gated load's cold-start
//! contract.

use keyhog_core::compute_spec_hash;
use keyhog_core::testing::{CoreTestApi, TestApi};
use keyhog_core::{
    CompanionSpec, DetectorSpec, MerkleIndex, MerkleLoadStatus, PatternSpec, Severity,
};

/// Build a fully-populated detector so every hashed field is exercised.
fn detector(id: &str, severity: Severity, regex: &str, keywords: &[&str]) -> DetectorSpec {
    DetectorSpec {
        kind: Default::default(),
        entropy_floor: Vec::new(),
        tests: Vec::new(),
        id: id.to_string(),
        name: id.to_string(),
        service: id.to_string(),
        severity,
        keywords: keywords.iter().map(|k| k.to_string()).collect(),
        min_confidence: None,
        patterns: vec![PatternSpec {
            regex: regex.to_string(),
            ..Default::default()
        }],
        companions: vec![],
        verify: None,
        // Default any newer optional spec fields so this exhaustive literal does
        // not break each time DetectorSpec grows a field (explicit fields win).
        ..Default::default()
    }
}

/// Lowercase-hex encode a 32-byte digest for hand-crafted on-disk JSON. Kept
/// local (the crate's canonical `hex_encode` is not part of the public surface);
/// asserted against `blake3` elsewhere so a divergence would surface.
fn hex32(bytes: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

// ── compute_spec_hash identity semantics ────────────────────────────────────

#[test]
fn spec_hash_is_deterministic_for_identical_input() {
    let a = detector("aws-key", Severity::High, "AKIA[0-9A-Z]{16}", &["akia"]);
    // Two independently-built but equal detector sets must hash byte-identically.
    let h1 = compute_spec_hash(std::slice::from_ref(&a));
    let h2 = compute_spec_hash(&[detector(
        "aws-key",
        Severity::High,
        "AKIA[0-9A-Z]{16}",
        &["akia"],
    )]);
    assert_eq!(
        h1, h2,
        "identical detector sets must produce identical spec hashes"
    );
    assert_eq!(h1.len(), 32, "spec hash is a 32-byte BLAKE3 digest");
}

#[test]
fn spec_hash_of_empty_detector_set_is_blake3_of_empty_input() {
    // No detectors => no key material fed to the hasher => finalize is BLAKE3
    // of the empty byte string. Pin the exact digest so an accidental salt or
    // seed byte prepended to the hasher is caught.
    let empty: [DetectorSpec; 0] = [];
    let got = compute_spec_hash(&empty);
    let expect = *blake3::hash(b"").as_bytes();
    assert_eq!(got, expect, "empty detector set must hash to BLAKE3(\"\")");
}

#[test]
fn spec_hash_changes_when_keyword_added() {
    let base = detector(
        "stripe",
        Severity::High,
        "sk_live_[0-9a-zA-Z]{24}",
        &["sk_live"],
    );
    let mut more = base.clone();
    more.keywords.push("stripe_key".into());
    assert_ne!(
        compute_spec_hash(std::slice::from_ref(&base)),
        compute_spec_hash(std::slice::from_ref(&more)),
        "adding a keyword must change the spec hash so the merkle cache invalidates"
    );
}

#[test]
fn spec_hash_removing_added_keyword_restores_original() {
    let base = detector("gh", Severity::Medium, "ghp_[0-9A-Za-z]{36}", &["ghp"]);
    let base_hash = compute_spec_hash(std::slice::from_ref(&base));

    let mut extended = base.clone();
    extended.keywords.push("github_token".into());
    let extended_hash = compute_spec_hash(std::slice::from_ref(&extended));
    assert_ne!(base_hash, extended_hash, "extended set must differ");

    // Remove the added keyword: the digest must return to the exact original.
    extended.keywords.pop();
    let reverted_hash = compute_spec_hash(std::slice::from_ref(&extended));
    assert_eq!(
        base_hash, reverted_hash,
        "removing the added keyword must restore the original digest exactly"
    );
}

#[test]
fn spec_hash_keyword_order_within_detector_is_invariant() {
    // Keywords are sorted before hashing, so declaration order must not matter.
    let ab = detector("svc", Severity::Low, "[A-Z]{20}", &["alpha", "beta"]);
    let ba = detector("svc", Severity::Low, "[A-Z]{20}", &["beta", "alpha"]);
    assert_eq!(
        compute_spec_hash(std::slice::from_ref(&ab)),
        compute_spec_hash(std::slice::from_ref(&ba)),
        "keyword declaration order within a detector must not affect the spec hash"
    );
}

#[test]
fn spec_hash_is_order_invariant_across_detector_reordering() {
    let a = detector("alpha", Severity::High, "A[0-9]{10}", &["a"]);
    let b = detector("beta", Severity::Low, "B[0-9]{10}", &["b"]);
    let forward = compute_spec_hash(&[a.clone(), b.clone()]);
    let reversed = compute_spec_hash(&[b, a]);
    assert_eq!(
        forward, reversed,
        "detector slice ordering must not change the spec hash (keys are sorted)"
    );

    // But a genuinely different corpus must differ.
    let c = detector("gamma", Severity::High, "C[0-9]{10}", &["c"]);
    let different =
        compute_spec_hash(&[detector("alpha", Severity::High, "A[0-9]{10}", &["a"]), c]);
    assert_ne!(
        forward, different,
        "a different detector set must hash differently"
    );
}

#[test]
fn spec_hash_changes_when_severity_changes() {
    let high = detector("d", Severity::High, "[A-Z]{16}", &["k"]);
    let low = detector("d", Severity::Low, "[A-Z]{16}", &["k"]);
    assert_ne!(
        compute_spec_hash(std::slice::from_ref(&high)),
        compute_spec_hash(std::slice::from_ref(&low)),
        "changing a detector's severity must change the spec hash"
    );
}

#[test]
fn spec_hash_changes_when_pattern_regex_changes() {
    let p1 = detector("d", Severity::High, "AKIA[0-9A-Z]{16}", &["akia"]);
    let p2 = detector("d", Severity::High, "AKIA[0-9A-Z]{20}", &["akia"]);
    assert_ne!(
        compute_spec_hash(std::slice::from_ref(&p1)),
        compute_spec_hash(std::slice::from_ref(&p2)),
        "changing a pattern's regex must change the spec hash"
    );
}

#[test]
fn spec_hash_changes_when_detector_id_changes() {
    let d1 = detector("id-one", Severity::High, "[A-Z]{16}", &["k"]);
    let d2 = detector("id-two", Severity::High, "[A-Z]{16}", &["k"]);
    assert_ne!(
        compute_spec_hash(std::slice::from_ref(&d1)),
        compute_spec_hash(std::slice::from_ref(&d2)),
        "the detector id is part of every hashed key; changing it must change the digest"
    );
}

#[test]
fn spec_hash_changes_when_companion_added() {
    let base = detector("d", Severity::High, "[A-Z]{16}", &["k"]);
    let mut with_companion = base.clone();
    with_companion.companions.push(CompanionSpec {
        name: "secret".into(),
        regex: "s=([A-Z]+)".into(),
        within_lines: 3,
        required: true,
    });
    assert_ne!(
        compute_spec_hash(std::slice::from_ref(&base)),
        compute_spec_hash(std::slice::from_ref(&with_companion)),
        "adding a companion pattern must change the spec hash"
    );
}

// ── spec-gated merkle load: cold-start contract ─────────────────────────────

#[test]
fn schema_version_mismatch_cold_starts() {
    let dir = tempfile::tempdir().unwrap();
    let cache = dir.path().join("merkle.idx");
    // A structurally-valid cache file carrying an incompatible schema version.
    // The current binary uses schema v4; write v99.
    let json = r#"{"version":99,"spec_hash":null,"written_at_ns":0,"entries":[]}"#;
    std::fs::write(&cache, json).unwrap();

    let spec = compute_spec_hash(&[detector("d", Severity::High, "[A-Z]{16}", &["k"])]);
    let report = MerkleIndex::load_with_spec_report(&cache, &spec);
    let status = report.status().clone();
    match status {
        MerkleLoadStatus::SchemaMismatch {
            path,
            version,
            expected,
        } => {
            assert_eq!(path, cache, "status must name the offending cache path");
            assert_eq!(version, 99, "reported on-disk version");
            assert_eq!(expected, 4, "current binary requires schema v4");
        }
        other => panic!("expected SchemaMismatch cold start, got {other:?}"),
    }
    // Cold start => empty in-memory index.
    let idx = report.into_index();
    assert_eq!(
        CoreTestApi::merkle_len(&TestApi, &idx),
        0,
        "schema mismatch must cold-start empty"
    );
}

#[test]
fn corrupted_cache_json_cold_starts() {
    let dir = tempfile::tempdir().unwrap();
    let cache = dir.path().join("merkle.idx");
    // Truncated / hand-corrupted cache content that is not valid JSON.
    std::fs::write(&cache, b"{ this is not valid json ]]").unwrap();

    let spec = compute_spec_hash(&[detector("d", Severity::High, "[A-Z]{16}", &["k"])]);
    let report = MerkleIndex::load_with_spec_report(&cache, &spec);
    match report.status().clone() {
        MerkleLoadStatus::ParseFailed { path, error } => {
            assert_eq!(path, cache, "status must name the unparseable cache path");
            assert!(
                !error.is_empty(),
                "parse error message must be captured for the operator"
            );
        }
        other => panic!("expected ParseFailed cold start, got {other:?}"),
    }
    let idx = report.into_index();
    assert_eq!(
        CoreTestApi::merkle_len(&TestApi, &idx),
        0,
        "corrupted cache must cold-start empty"
    );
}

#[test]
fn detector_spec_change_cold_starts_and_matching_spec_reloads() {
    let dir = tempfile::tempdir().unwrap();
    let cache = dir.path().join("merkle.idx");

    // Persist one entry bound to spec-hash A. Use a tiny mtime so the racy-clean
    // guard (which drops entries whose mtime is in the same second as, or after,
    // the index write) retains it on reload.
    let idx = CoreTestApi::merkle_empty(&TestApi);
    let content_hash = CoreTestApi::merkle_hash_content(&TestApi, b"cached-file-body");
    CoreTestApi::merkle_record_with_metadata(
        &TestApi,
        &idx,
        std::path::PathBuf::from("src/lib.rs"),
        100,
        16,
        content_hash,
    );
    let spec_a = compute_spec_hash(&[detector("d", Severity::High, "[A-Z]{16}", &["k"])]);
    idx.save_with_spec(&cache, &spec_a)
        .expect("save_with_spec must succeed");

    // Loading with a DIFFERENT spec hash (a keyword was added) must cold-start.
    let spec_b = compute_spec_hash(&[detector("d", Severity::High, "[A-Z]{16}", &["k", "extra"])]);
    assert_ne!(
        spec_a, spec_b,
        "the two detector corpora must have distinct spec hashes"
    );
    let changed = MerkleIndex::load_with_spec_report(&cache, &spec_b);
    match changed.status().clone() {
        MerkleLoadStatus::SpecChanged { path } => {
            assert_eq!(
                path, cache,
                "SpecChanged must name the invalidated cache path"
            );
        }
        other => panic!("expected SpecChanged cold start, got {other:?}"),
    }
    assert_eq!(
        CoreTestApi::merkle_len(&TestApi, &changed.into_index()),
        0,
        "a detector-spec change must cold-start empty (no stale skips)"
    );

    // Loading with the ORIGINAL spec hash must trust the cache and reload it.
    let reload = MerkleIndex::load_with_spec_report(&cache, &spec_a);
    match reload.status().clone() {
        MerkleLoadStatus::Loaded { path, entries } => {
            assert_eq!(path, cache, "Loaded must name the trusted cache path");
            assert_eq!(entries, 1, "the single persisted entry must be retained");
        }
        other => panic!("expected Loaded, got {other:?}"),
    }
    let reloaded = reload.into_index();
    assert_eq!(CoreTestApi::merkle_len(&TestApi, &reloaded), 1);
    assert_eq!(
        CoreTestApi::merkle_lookup(&TestApi, &reloaded, std::path::Path::new("src/lib.rs")),
        Some((100, 16, content_hash)),
        "the reloaded entry value must be byte-identical to what was saved"
    );
}

#[test]
fn missing_cache_reports_missing_status() {
    let dir = tempfile::tempdir().unwrap();
    let cache = dir.path().join("does-not-exist.idx");
    let spec = compute_spec_hash(&[detector("d", Severity::High, "[A-Z]{16}", &["k"])]);
    let report = MerkleIndex::load_with_spec_report(&cache, &spec);
    match report.status().clone() {
        MerkleLoadStatus::Missing { path } => {
            assert_eq!(path, cache, "Missing must name the probed cache path");
        }
        other => panic!("expected Missing, got {other:?}"),
    }
    assert_eq!(
        CoreTestApi::merkle_len(&TestApi, &report.into_index()),
        0,
        "a missing cache yields an empty index"
    );
}

#[test]
fn invalid_entry_hash_cold_starts_even_with_matching_spec() {
    let dir = tempfile::tempdir().unwrap();
    let cache = dir.path().join("merkle.idx");

    // Hand-craft a v4 cache whose spec_hash MATCHES (so it passes the spec gate)
    // but whose single entry carries a non-hex BLAKE3 digest. The loader must
    // fail closed on the corrupt entry rather than trust a partial cache.
    let spec = compute_spec_hash(&[detector("d", Severity::High, "[A-Z]{16}", &["k"])]);
    let spec_hex = hex32(&spec);
    let json = format!(
        r#"{{"version":4,"spec_hash":"{spec_hex}","written_at_ns":0,"entries":[{{"path":"src/a.rs","chunk_offset":0,"mtime_ns":1,"size":2,"last_seen_order":0,"hash":"not-a-valid-hex-digest"}}]}}"#
    );
    std::fs::write(&cache, json).unwrap();

    let report = MerkleIndex::load_with_spec_report(&cache, &spec);
    match report.status().clone() {
        MerkleLoadStatus::InvalidEntryHash {
            path,
            entry_path,
            hash,
        } => {
            assert_eq!(path, cache);
            assert_eq!(
                entry_path, "src/a.rs",
                "must name the corrupt entry's source path"
            );
            assert_eq!(
                hash, "not-a-valid-hex-digest",
                "must echo the invalid hash string"
            );
        }
        other => panic!("expected InvalidEntryHash cold start, got {other:?}"),
    }
    assert_eq!(
        CoreTestApi::merkle_len(&TestApi, &report.into_index()),
        0,
        "an invalid persisted entry hash must cold-start the whole index empty"
    );
}
