//! R5-T engine chunk boundary: shopify-access-token split across seam must reassemble.

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::CompiledScanner;
use std::path::PathBuf;

#[test]
fn r5t_chunk_boundary_shopify_token_split_reassembled() {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop();
    d.pop();
    d.push("detectors");
    let scanner = CompiledScanner::compile(keyhog_core::load_detectors(&d).expect("detectors"))
        .expect("compile");
    let secret = "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";
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
    // `shpat_` is the Shopify ADMIN API token shape, owned by
    // `shopify-admin-api-token`. (The generic `shopify-access-token` detector
    // owns only the `shpca_` custom-app shape - it no longer double-claims
    // `shpat_`.)
    let found = results.iter().flatten().any(|m| {
        m.detector_id.as_ref() == "shopify-admin-api-token" && m.credential.as_ref() == secret
    });
    assert!(
        found,
        "shopify-admin-api-token split across chunk seam must reassemble"
    );
}
