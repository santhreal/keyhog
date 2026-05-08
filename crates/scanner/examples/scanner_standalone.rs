use keyhog_core::{Chunk, ChunkMetadata, DetectorSpec, PatternSpec, Severity};
use keyhog_scanner::CompiledScanner;

fn main() -> Result<(), keyhog_scanner::ScanError> {
    let scanner = CompiledScanner::compile(vec![DetectorSpec {
        id: "demo-token".into(),
        name: "Demo Token".into(),
        service: "demo".into(),
        severity: Severity::High,
        patterns: vec![PatternSpec {
            regex: "demo_[A-Z0-9]{8}".into(),
            description: None,
            group: None,
        }],
        companions: Vec::new(),
        verify: None,
        keywords: vec!["demo_".into()],
    }])?;

    let matches = scanner.scan(&Chunk {
        data: "TOKEN=demo_ABC12345".into(),
        metadata: ChunkMetadata {
            base_offset: 0,
            source_type: "example".into(),
            path: Some("example.env".into()),
            commit: None,
            author: None,
            date: None,
                    mtime_ns: None,
            size_bytes: None,
},
    });

    println!(
        "detectors={} patterns={}",
        scanner.detector_count(),
        scanner.pattern_count()
    );
    println!("matches={}", matches.len());
    Ok(())
}
