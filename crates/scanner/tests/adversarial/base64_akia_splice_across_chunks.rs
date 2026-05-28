//! Base64-wrapped AKIA split across chunks must still decode and fire.

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::CompiledScanner;
use std::path::PathBuf;

#[test]
fn base64_akia_splice_across_chunks() {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop();
    d.pop();
    d.push("detectors");
    let scanner = CompiledScanner::compile(keyhog_core::load_detectors(&d).expect("detectors"))
        .expect("compile");

    let secret = "AKIAQYLPMN5HFIQR7XYA";
    let encoded = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        secret.as_bytes(),
    );
    let split = encoded.len() / 2;
    let prefix = format!("CONFIG_B64={}", &encoded[..split]);
    let prefix_len = prefix.len();
    let suffix = encoded[split..].to_string();

    let chunk_a = Chunk {
        data: prefix.into(),
        metadata: ChunkMetadata {
            source_type: "adversarial".into(),
            path: Some("b64.env".into()),
            base_offset: 0,
            ..Default::default()
        },
    };
    let chunk_b = Chunk {
        data: suffix.into(),
        metadata: ChunkMetadata {
            source_type: "adversarial".into(),
            path: Some("b64.env".into()),
            base_offset: prefix_len,
            ..Default::default()
        },
    };

    let results = scanner.scan_coalesced(&[chunk_a, chunk_b]);
    let found = results
        .iter()
        .flatten()
        .any(|m| m.detector_id.as_ref() == "aws-access-key" && m.credential.as_ref() == secret);
    assert!(found, "base64 splice across chunks must still surface AKIA");
}
