//! Scanner must survive empty chunk without panic and without false positives.

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::CompiledScanner;

fn detector_dir() -> std::path::PathBuf {
    let mut d = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop();
    d.pop();
    d.push("detectors");
    d
}

#[test]
fn empty_chunk_produces_zero_matches() {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile");
    let chunk = Chunk {
        data: String::new().into(),
        metadata: ChunkMetadata {
            source_type: "test".into(),
            path: Some("empty.txt".into()),
            base_offset: 0,
            ..Default::default()
        },
    };
    let matches = scanner.scan(&chunk);
    assert_eq!(
        matches.len(),
        0,
        "empty chunk must not produce findings, got {:?}",
        matches
            .iter()
            .map(|m| m.detector_id.as_ref())
            .collect::<Vec<_>>()
    );
}
