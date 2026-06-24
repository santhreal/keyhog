use keyhog_core::{Chunk, ChunkMetadata, DetectorSpec, PatternSpec, Severity};
use keyhog_scanner::{CompiledScanner, ScanBackend};

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
            client_safe: false,
        }],
        companions: vec![],
        verify: None,
        keywords: vec!["kh_history_secret_".into()],
        min_confidence: None,
        ..Default::default()
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

#[test]
fn git_history_hyphen_source_type_is_preinterned() {
    let source =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/static_intern.rs"))
            .expect("static interner source readable");
    assert!(
        source.contains("\"git-history\""),
        "git-history source_type must be pre-seeded for allocation-free match metadata"
    );
}
