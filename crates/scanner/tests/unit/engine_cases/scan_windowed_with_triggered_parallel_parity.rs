use keyhog_core::{Chunk, ChunkMetadata, DetectorSpec, PatternSpec, RawMatch, Severity};
use keyhog_scanner::testing::scan_windowed_with_triggered_for_test;
use keyhog_scanner::CompiledScanner;

fn detector() -> DetectorSpec {
    DetectorSpec {
        tests: Vec::new(),
        id: "windowed-trigger-token".into(),
        name: "Windowed Trigger Token".into(),
        service: "windowed-trigger".into(),
        severity: Severity::High,
        patterns: vec![PatternSpec {
            regex: "tok_live_[A-Za-z0-9]{32}".into(),
            description: None,
            group: None,
            client_safe: false,
        }],
        companions: vec![],
        verify: None,
        keywords: vec!["tok_live_".into()],
        min_confidence: None,
        ..Default::default()
    }
}

fn canonical(matches: &[RawMatch]) -> Vec<(String, String, usize, Option<usize>)> {
    let mut rows = matches
        .iter()
        .filter(|m| m.detector_id.as_ref() == "windowed-trigger-token")
        .map(|m| {
            (
                m.detector_id.to_string(),
                m.credential.to_string(),
                m.location.offset,
                m.location.line,
            )
        })
        .collect::<Vec<_>>();
    rows.sort();
    rows
}

#[test]
fn coalesced_triggered_large_chunk_matches_windowed_scan() {
    let scanner = CompiledScanner::compile(vec![detector()]).expect("scanner compile");
    let token = "tok_live_aZ9kQ2mX7pL4rT8wE1nB6vY3cF5dH0jK";
    let mut text = String::with_capacity(1024 * 1024 + 256);
    text.push_str(&"a".repeat(1024 * 1024 - 24));
    text.push('\n');
    text.push_str("export TOKEN=");
    text.push_str(token);
    text.push('\n');
    text.push_str(&"b".repeat(256));
    let chunk = Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "unit".into(),
            path: Some("large.env".into()),
            ..Default::default()
        },
    };

    scanner.clear_fragment_cache();
    let serial = scanner.scan(&chunk);
    scanner.clear_fragment_cache();
    let triggered = scan_windowed_with_triggered_for_test(&scanner, &chunk, &[1]);

    let serial_rows = canonical(&serial);
    let triggered_rows = canonical(&triggered);
    assert_eq!(triggered_rows, serial_rows);
    assert_eq!(
        triggered_rows,
        vec![(
            "windowed-trigger-token".to_string(),
            token.to_string(),
            1024 * 1024 - 24 + 1 + "export TOKEN=".len(),
            Some(2)
        )]
    );
}
