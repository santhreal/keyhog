//! Empty corpus must produce zero findings across the full detector set.

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::CompiledScanner;
use std::path::PathBuf;

#[test]
fn empty_corpus_zero_findings() {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop(); d.pop(); d.push("detectors");
    let scanner = CompiledScanner::compile(keyhog_core::load_detectors(&d).expect("detectors"))
        .expect("compile");

    let chunk = Chunk {
        data: String::new().into(),
        metadata: ChunkMetadata {
            source_type: "adversarial".into(),
            path: Some("empty.corpus".into()),
            ..Default::default()
        },
    };
    let matches = scanner.scan(&chunk);
    assert_eq!(
        matches.len(),
        0,
        "empty corpus must not produce spurious findings: {:?}",
        matches.iter().map(|m| m.detector_id.as_ref()).collect::<Vec<_>>()
    );
}
