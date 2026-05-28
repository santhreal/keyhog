//! R5-T-SCAN reverse decode must surface `slack-bot-token`.

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::CompiledScanner;
use std::path::PathBuf;

#[test]
fn reverse_slack_token_reversed() {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop();
    d.pop();
    d.push("detectors");
    let scanner = CompiledScanner::compile(keyhog_core::load_detectors(&d).expect("detectors"))
        .expect("compile");
    let secret = "xoxb-1234567890-1234567890123-abcdefghijklmnopqrstuvwx";
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
        matches.iter().any(|m| m.detector_id.as_ref() == "slack-bot-token" && m.credential.as_ref() == secret),
        "reverse-encoded slack-bot-token must surface; matches={:?}",
        matches.iter().map(|m| (m.detector_id.as_ref(), m.credential.as_ref())).collect::<Vec<_>>()
    );
}
