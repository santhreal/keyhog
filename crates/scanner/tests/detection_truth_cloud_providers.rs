//! Detection-truth: cloud provider secrets (#177/#184). Azure storage account
//! keys and mongodb+srv connection strings — pinned to the specific detector +
//! value (Law 6). ML-independent; run without `ml` while weights are mid-retrain.

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::{CompiledScanner, ScanBackend};

fn detector_ids(text: &str) -> Vec<String> {
    let detectors = keyhog_core::embedded_detector_specs().to_vec();
    let scanner = CompiledScanner::compile(detectors).expect("scanner compile");
    let chunk = Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "cloud-test".into(),
            path: Some("s.txt".into()),
            base_offset: 0,
            ..Default::default()
        },
    };
    scanner
        .scan_chunks_with_backend(std::slice::from_ref(&chunk), ScanBackend::CpuFallback)
        .iter()
        .flat_map(|per_chunk| per_chunk.iter())
        .map(|m| m.detector_id.to_string())
        .collect()
}

fn assert_fires(text: &str, want_id: &str) {
    let ids = detector_ids(text);
    assert!(
        ids.iter().any(|id| id == want_id),
        "expected `{want_id}` on {text:?}; got {ids:?}"
    );
}

#[test]
fn azure_storage_account_key_88char() {
    // Real Azure account keys are 88-char base64 (64 raw bytes).
    assert_fires(
        "AccountKey=YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXpBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWjAxMjM0NTY3ODkr/g==",
        "azure-storage-account-key",
    );
}

#[test]
fn mongodb_srv_connection_string() {
    assert_fires(
        "MONGO=mongodb+srv://admin:Str0ngMongoPwd@cluster0.example.com/db",
        "mongodb-connection-string",
    );
}
