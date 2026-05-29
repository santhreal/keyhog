//! R5-T engine chunk boundary: cloudflare-api-token split across seam must reassemble.

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::CompiledScanner;
use std::path::PathBuf;

#[test]
fn r5t_chunk_boundary_cloudflare_token_split_reassembled() {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop();
    d.pop();
    d.push("detectors");
    let scanner = CompiledScanner::compile(keyhog_core::load_detectors(&d).expect("detectors"))
        .expect("compile");
    // Context-required detector: the `cloudflare_api_token=` anchor and the
    // 40-char value straddle the seam together. The credential is the
    // captured value group, not the full `key=value` string.
    let secret = "cloudflare_api_token=Xy7Kp2Lm9Qr4Tv6Wz1Bn8Ch5Df3Gj0Hs4iU2oPqR";
    let split = 12;
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
            path: Some("chunk-r5t.txt".into()),
            base_offset: 0,
            ..Default::default()
        },
    };
    let chunk_b = Chunk {
        data: data_b.into(),
        metadata: ChunkMetadata {
            source_type: "adversarial".into(),
            path: Some("chunk-r5t.txt".into()),
            base_offset: len_a,
            ..Default::default()
        },
    };
    let results = scanner.scan_coalesced(&[chunk_a, chunk_b]);
    let found = results.iter().flatten().any(|m| {
        m.detector_id.as_ref() == "cloudflare-api-token"
            && m.credential.as_ref() == "Xy7Kp2Lm9Qr4Tv6Wz1Bn8Ch5Df3Gj0Hs4iU2oPqR"
    });
    assert!(
        found,
        "cloudflare-api-token split across chunk seam must reassemble"
    );
}
