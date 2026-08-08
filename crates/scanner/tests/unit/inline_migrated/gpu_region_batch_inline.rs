//! Migrated from src/engine/gpu_region_batch.rs

use keyhog_scanner::engine::gpu_region_batch::{GpuPipelineOverlapTrace, GpuSlotOccupancy};

#[test]
fn test_pipeline_overlap_tracing() {
    let trace = GpuPipelineOverlapTrace::record(
        GpuSlotOccupancy::Uploading,
        GpuSlotOccupancy::Computing,
        true,
    );
    assert!(trace.overlap_active);
    assert!(trace.output_order_preserved);
}
