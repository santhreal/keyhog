use keyhog_core::{
    dedup_cross_detector, dedup_matches, Chunk, ChunkMetadata, DedupScope, DetectorSpec,
    PatternSpec, Severity,
};
use keyhog_scanner::resolution::resolve_matches;
use keyhog_scanner::CompiledScanner;

const MAX_SCAN_CHUNK_BYTES: usize = 1024 * 1024;
const WINDOW_OVERLAP_BYTES: usize = 128 * 1024;
const TOKEN_START: usize = 950_000;

fn detector() -> DetectorSpec {
    DetectorSpec {
        tests: Vec::new(),
        id: "windowed-overlap-token".into(),
        name: "Windowed Overlap Token".into(),
        service: "windowed-overlap".into(),
        severity: Severity::High,
        patterns: vec![PatternSpec {
            regex: "tok_overlap_[A-Za-z0-9]{32}".into(),
            description: None,
            group: None,
            client_safe: false,
            weak_anchor: false,
        }],
        companions: vec![],
        verify: None,
        keywords: vec!["tok_overlap_".into()],
        min_confidence: None,
        ..Default::default()
    }
}

#[test]
fn scan_windowed_overlap_dedups_end_to_end() {
    assert!(
        TOKEN_START >= MAX_SCAN_CHUNK_BYTES - WINDOW_OVERLAP_BYTES,
        "fixture token must start inside the second window's overlap"
    );

    let scanner = CompiledScanner::compile(vec![detector()]).expect("scanner compile");
    let token = "tok_overlap_aZ9kQ2mX7pL4rT8wE1nB6vY3cF5dH0jK";
    let prefix = "\nexport TOKEN=";
    let filler_len = TOKEN_START - prefix.len();
    let mut text = String::with_capacity(MAX_SCAN_CHUNK_BYTES + 2048);
    text.push_str(&"a".repeat(filler_len));
    text.push_str(prefix);
    assert_eq!(text.len(), TOKEN_START);
    text.push_str(token);
    text.push('\n');
    text.push_str(&"b".repeat(MAX_SCAN_CHUNK_BYTES + 512 - text.len()));
    assert!(text.len() > MAX_SCAN_CHUNK_BYTES);

    let chunk = Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "unit".into(),
            path: Some("overlap.env".into()),
            ..Default::default()
        },
    };

    scanner.clear_fragment_cache();
    let raw = scanner.scan(&chunk);
    let raw_rows = raw
        .iter()
        .filter(|m| m.detector_id.as_ref() == "windowed-overlap-token")
        .map(|m| {
            (
                m.detector_id.as_ref().to_string(),
                m.credential.as_ref().to_string(),
                m.location.offset,
                m.location.line,
            )
        })
        .collect::<Vec<_>>();

    assert_eq!(
        raw_rows,
        vec![(
            "windowed-overlap-token".to_string(),
            token.to_string(),
            TOKEN_START,
            Some(2)
        )],
        "the production windowed scan path must collapse duplicate raw hits from adjacent overlapping windows"
    );

    let reported =
        dedup_cross_detector(dedup_matches(resolve_matches(raw), &DedupScope::Credential));
    assert_eq!(reported.len(), 1);
    let finding = &reported[0];
    assert_eq!(finding.detector_id.as_ref(), "windowed-overlap-token");
    assert_eq!(finding.credential.as_ref(), token);
    assert_eq!(finding.primary_location.offset, TOKEN_START);
    assert_eq!(finding.primary_location.line, Some(2));
    assert!(
        finding.additional_locations.is_empty(),
        "the final report grouping must not retain a second overlap alias"
    );
}
