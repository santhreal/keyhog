//! Migrated from src/gpu/backend/resident_evidence.rs

use keyhog_scanner::testing::resident_evidence::{
    CudaTimelineEvidence, WgpuQueueOverlapProof, METAL_ASYNC_UNPROVED_BOUNDARY_DOC,
};

#[test]
fn test_cuda_timeline_evidence() {
    let evidence = CudaTimelineEvidence::record(100, 200);
    assert!(evidence.is_async_proven());
}

#[test]
fn test_cuda_timeline_evidence_invalid_zero_ts() {
    let evidence = CudaTimelineEvidence::record(0, 200);
    assert!(!evidence.is_async_proven());
}

#[test]
fn test_wgpu_queue_overlap_proof() {
    let proof = WgpuQueueOverlapProof::prove(true, true, true).unwrap();
    assert!(proof.overlap_demonstrated);
    assert!(proof.parity_preserved);
}

#[test]
fn test_wgpu_queue_overlap_proof_rejects_inactive_slot() {
    assert!(WgpuQueueOverlapProof::prove(false, true, true).is_err());
    assert!(WgpuQueueOverlapProof::prove(true, false, true).is_err());
}

#[test]
fn test_metal_async_doc_boundary() {
    assert!(METAL_ASYNC_UNPROVED_BOUNDARY_DOC.contains("Metal async execution"));
}
