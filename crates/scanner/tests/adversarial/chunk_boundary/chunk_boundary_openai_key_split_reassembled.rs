//! R5-T-SCAN engine chunk boundary: openai key split reassembled.

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::CompiledScanner;
use std::path::PathBuf;

#[test]
fn chunk_boundary_openai_key_split_reassembled() {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop(); d.pop(); d.push("detectors");
    let scanner = CompiledScanner::compile(keyhog_core::load_detectors(&d).expect("detectors"))
        .expect("compile");

    let secret = "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890AB";
    let split = 14;
    let pad = "z\n".repeat(4096);
    let mut data_a = pad.clone();
    data_a.push_str(&secret[..split]);
    let len_a = data_a.len();
    let mut data_b = secret[split..].to_string();
    data_b.push_str("\n");

    let chunk_a = Chunk {
        data: data_a.into(),
        metadata: ChunkMetadata {
            source_type: "adversarial".into(),
            path: Some("chunk-a.txt".into()),
            base_offset: 0,
            ..Default::default()
        },
    };
    let chunk_b = Chunk {
        data: data_b.into(),
        metadata: ChunkMetadata {
            source_type: "adversarial".into(),
            path: Some("chunk-a.txt".into()),
            base_offset: len_a,
            ..Default::default()
        },
    };

    let results = scanner.scan_coalesced(&[chunk_a, chunk_b]);
    let found = results.iter().flatten().any(|m| m.detector_id.as_ref() == "openai-api-key" && m.credential.as_ref() == "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890AB");
    assert!(found, "openai-api-key split across chunk seam must reassemble");
}
