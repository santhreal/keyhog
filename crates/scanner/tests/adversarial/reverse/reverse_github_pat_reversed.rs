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
    // A real github-classic-pat (valid 36-char checksum). The prior
    // ghp_abc…AB had a 38-char body + bad checksum, so the reverse decode
    // surfaced it only as entropy-token/generic-password (the specific
    // detector cannot match a malformed token). See the github-classic-pat
    // contract positive.
    let secret = "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";
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
