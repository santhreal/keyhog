use keyhog_core::{Chunk, ChunkMetadata, DetectorSpec, PatternSpec, Severity};
use keyhog_scanner::CompiledScanner;

fn main() -> Result<(), keyhog_scanner::ScanError> {
    let scanner = CompiledScanner::compile(vec![DetectorSpec {
        kind: Default::default(),
        entropy_floor: Vec::new(),
        tests: Vec::new(),
        id: "demo-token".into(),
        name: "Demo Token".into(),
        service: "demo".into(),
        severity: Severity::High,
        patterns: vec![PatternSpec {
            regex: "demo_[A-Z0-9]{8}".into(),
            description: None,
            group: None,
            required_literals: Vec::new(),
            client_safe: false,
            weak_anchor: false,
            structural_password_slot: false,
        }],
        companions: Vec::new(),
        verify: None,
        keywords: vec!["demo_".into()],
        min_confidence: None,
        ..Default::default()
    }])?;

    let matches = scanner.scan(&Chunk {
        data: "TOKEN=demo_ABC12345".into(),
        metadata: ChunkMetadata {
            base_offset: 0,
            base_line: 0,
            source_type: "example".into(),
            path: Some("example.env".into()),
            commit: None,
            author: None,
            date: None,
            mtime_ns: None,
            size_bytes: None,
            ..Default::default()
        },
    });

    println!(
        "detectors={} patterns={}",
        scanner.runtime_status().detector_count,
        scanner.runtime_status().pattern_count
    );
    println!("matches={}", matches.len());
    Ok(())
}
