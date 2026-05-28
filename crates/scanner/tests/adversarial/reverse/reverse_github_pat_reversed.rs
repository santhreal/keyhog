//! R5-T-SCAN reverse decode must surface `github-classic-pat`.

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::CompiledScanner;
use std::path::PathBuf;

#[test]
fn reverse_github_pat_reversed() {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop();
    d.pop();
    d.push("detectors");
    let scanner = CompiledScanner::compile(keyhog_core::load_detectors(&d).expect("detectors"))
        .expect("compile");
    let secret = "ghp_abcdefghijklmnopqrstuvwxyz1234567890AB";
    let reversed: String = secret.chars().rev().collect();
    let chunk = Chunk {
        data: format!("token = \"{reversed}\"").into(),
        metadata: ChunkMetadata {
            source_type: "adversarial".into(),
            path: Some("reversed.txt".into()),
            ..Default::default()
        },
    };
    let matches = scanner.scan(&chunk);
    assert!(
        matches
            .iter()
            .any(|m| m.detector_id.as_ref() == "github-classic-pat"
                && m.credential.as_ref() == secret),
        "reverse-encoded github-classic-pat must surface; matches={:?}",
        matches
            .iter()
            .map(|m| (m.detector_id.as_ref(), m.credential.as_ref()))
            .collect::<Vec<_>>()
    );
}
