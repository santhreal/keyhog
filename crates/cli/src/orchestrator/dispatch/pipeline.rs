const COALESCED_BATCH_CHUNK_LIMIT: usize = 4096;
const COALESCED_PIPELINE_MAX_DEPTH: usize = 3;

#[derive(Debug, Clone, Copy)]
pub(super) struct CoalescedPipelinePlan {
    pub(super) batch_chunk_limit: usize,
    pub(super) batch_bytes_budget: usize,
    pub(super) pipeline_depth: usize,
}

pub(super) fn coalesced_pipeline_plan() -> CoalescedPipelinePlan {
    let engine_cap = keyhog_scanner::gpu_batch_input_limit();
    let caps = keyhog_scanner::hw_probe::probe_hardware();
    let total_ram_bytes = match caps.total_memory_mb {
        Some(mb) => (mb as usize) * 1024 * 1024,
        None => 0,
    };
    // Pipeline depth is derived below from the same hardware probe. Assume the
    // max depth for the headroom clamp so worst-case resident memory remains
    // under 1/8 of system RAM even on big-VRAM cards.
    let headroom_cap = total_ram_bytes / (8 * COALESCED_PIPELINE_MAX_DEPTH);
    let batch_bytes_budget = if headroom_cap == 0 {
        engine_cap
    } else {
        engine_cap.min(headroom_cap)
    };
    let pipeline_depth = match caps.total_memory_mb {
        Some(mb) if mb >= 32 * 1024 => 3,
        Some(mb) if mb >= 16 * 1024 => 2,
        _ => 1,
    };

    CoalescedPipelinePlan {
        batch_chunk_limit: COALESCED_BATCH_CHUNK_LIMIT,
        batch_bytes_budget,
        pipeline_depth,
    }
}
