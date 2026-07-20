use keyhog_core::{Chunk, ChunkMetadata, DetectorSpec, PatternSpec, RawMatch, Severity};
use keyhog_scanner::{CompiledScanner, ScanBackend};
use std::sync::Arc;

fn detector() -> DetectorSpec {
    DetectorSpec {
        tests: Vec::new(),
        id: "history-severity-token".into(),
        name: "History Severity Token".into(),
        service: "history-severity".into(),
        severity: Severity::High,
        patterns: vec![PatternSpec {
            regex: "kh_history_secret_[A-Za-z0-9]{16}".into(),
            description: None,
            group: None,
            required_literals: Vec::new(),
            client_safe: false,
            weak_anchor: false,
        }],
        companions: vec![],
        verify: None,
        keywords: vec!["kh_history_secret_".into()],
        min_confidence: None,
        ..keyhog_scanner::testing::named_detector_fixture_defaults()
    }
}

fn scan_source_type(source_type: &str) -> Vec<(String, Severity)> {
    let scanner = CompiledScanner::compile(vec![detector()]).expect("scanner compile");
    let chunk = Chunk {
        data: "token=kh_history_secret_A1b2C3d4E5f6G7h8\n".into(),
        metadata: ChunkMetadata {
            source_type: source_type.into(),
            path: Some("secret.env".into()),
            ..Default::default()
        },
    };
    let matches = scanner.scan_chunks_with_backend(&[chunk], ScanBackend::CpuFallback);
    let rows = matches.first().expect("scanner must return a chunk bucket");
    assert!(!rows.is_empty(), "detector must match fixture");
    rows.iter()
        .map(|hit| (hit.detector_id.to_string(), hit.severity))
        .collect()
}

fn detector_severity(rows: &[(String, Severity)]) -> Severity {
    rows.iter()
        .find_map(|(id, severity)| (id == "history-severity-token").then_some(*severity))
        .expect("named detector finding must be present")
}

#[test]
fn git_history_hyphen_source_type_downgrades_severity() {
    let filesystem = scan_source_type("filesystem");
    assert_eq!(detector_severity(&filesystem), Severity::High);

    for source_type in ["git/history", "git-history"] {
        let rows = scan_source_type(source_type);
        assert_eq!(detector_severity(&rows), Severity::Medium);
        assert!(
            rows.iter()
                .all(|(_, severity)| *severity <= Severity::Medium),
            "{source_type} findings must not retain live-source high severity: {rows:?}"
        );
    }
}

/// `location.source` Arcs for a single scanner scanning two identical chunks of
/// `source_type`. A scanner-wide static interner is cloned per scan but built
/// once per scanner, while the per-scan metadata interner is rebuilt per chunk
/// so a PRE-SEEDED source_type resolves to the same shared `Arc<str>` across both
/// chunk buckets, whereas an un-seeded one allocates a fresh Arc per chunk.
fn source_arcs_over_two_chunks(source_type: &str) -> (Arc<str>, Arc<str>) {
    let scanner = CompiledScanner::compile(vec![detector()]).expect("scanner compile");
    let chunk = || Chunk {
        data: "token=kh_history_secret_A1b2C3d4E5f6G7h8\n".into(),
        metadata: ChunkMetadata {
            source_type: source_type.into(),
            path: Some("secret.env".into()),
            ..Default::default()
        },
    };
    let buckets = scanner.scan_chunks_with_backend(&[chunk(), chunk()], ScanBackend::CpuFallback);
    let hit_source = |bucket: &[RawMatch]| {
        bucket
            .iter()
            .find(|hit| &*hit.detector_id == "history-severity-token")
            .expect("named detector finding must be present")
            .location
            .source
            .clone()
    };
    (hit_source(&buckets[0]), hit_source(&buckets[1]))
}

#[test]
fn git_history_source_type_resolves_to_shared_interned_arc() {
    // Pre-seeded: both chunks' matches share one Arc (allocation-free metadata).
    let (a, b) = source_arcs_over_two_chunks("git-history");
    assert_eq!(a.as_ref(), "git-history");
    assert!(
        Arc::ptr_eq(&a, &b),
        "pre-seeded git-history source_type must resolve to one shared Arc across chunks"
    );

    // Control: an un-seeded source_type is NOT in the static interner, so each
    // chunk's per-scan interner allocates a distinct Arc, proving the seeding,
    // not just Arc reuse, is what shares the git-history case.
    let (c, d) = source_arcs_over_two_chunks("kh-unseeded-control-source");
    assert!(
        !Arc::ptr_eq(&c, &d),
        "an un-seeded source_type must not resolve through the pre-seeded static interner"
    );
}
