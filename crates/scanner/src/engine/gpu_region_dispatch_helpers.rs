use super::gpu_region_batch::{
    region_presence_batch_byte_limit, region_presence_batch_len, region_presence_ref_batch_len,
    region_presence_ref_shards, region_presence_shards,
};
use super::phase2_gpu_dfa::{Phase2GpuDfaAdmission, Phase2GpuDfaCatalog};

pub(super) fn mib_per_second(bytes: usize, elapsed: std::time::Duration) -> f64 {
    if bytes == 0 || elapsed.is_zero() {
        return 0.0;
    }
    bytes as f64 / (1024.0 * 1024.0) / elapsed.as_secs_f64()
}

#[cfg(test)]
thread_local! {
    static TEST_WINDOW_REDUCTION_ALLOCATIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
pub(super) fn reset_test_window_reduction_allocations() {
    TEST_WINDOW_REDUCTION_ALLOCATIONS.with(|count| count.set(0));
}

#[cfg(test)]
pub(super) fn test_window_reduction_allocations() -> usize {
    TEST_WINDOW_REDUCTION_ALLOCATIONS.with(std::cell::Cell::get)
}

#[cfg(test)]
pub(super) fn record_test_window_reduction_allocation() {
    TEST_WINDOW_REDUCTION_ALLOCATIONS.with(|count| count.set(count.get().saturating_add(1)));
}

pub(super) fn append_phase2_gpu_admission(
    merged: &mut Phase2GpuDfaAdmission,
    mut shard: Phase2GpuDfaAdmission,
    expected_rows: usize,
) -> std::result::Result<(), String> {
    if shard.admitted.len() != expected_rows || shard.complete.len() != expected_rows {
        return Err(format!(
            "phase-2 GPU admission shard returned admitted={} and complete={} row(s), need {expected_rows}",
            shard.admitted.len(),
            shard.complete.len()
        ));
    }
    merged
        .admitted
        .try_reserve(shard.admitted.len())
        .map_err(|error| format!("phase-2 GPU admitted-row merge reserve failed: {error}"))?;
    merged
        .complete
        .try_reserve(shard.complete.len())
        .map_err(|error| format!("phase-2 GPU complete-row merge reserve failed: {error}"))?;
    merged.admitted.append(&mut shard.admitted);
    merged.complete.append(&mut shard.complete);
    merged.matches_seen = merged
        .matches_seen
        .checked_add(shard.matches_seen)
        .ok_or_else(|| "phase-2 GPU match count overflow across shards".to_string())?;
    Ok(())
}

pub(super) fn scan_phase2_gpu_chunks_sharded(
    catalog: &Phase2GpuDfaCatalog,
    backend: &dyn vyre::VyreBackend,
    chunks: &[keyhog_core::Chunk],
) -> std::result::Result<Phase2GpuDfaAdmission, String> {
    let byte_limit = region_presence_batch_byte_limit(backend.id());
    if region_presence_batch_len(chunks)? <= byte_limit {
        return catalog.scan_admission_chunks(backend, chunks);
    }
    let shards = region_presence_shards(chunks, byte_limit)?;
    let mut merged = Phase2GpuDfaAdmission {
        admitted: Vec::new(),
        complete: Vec::new(),
        matches_seen: 0,
    };
    merged
        .admitted
        .try_reserve(chunks.len())
        .map_err(|error| format!("phase-2 GPU admitted-row reserve failed: {error}"))?;
    merged
        .complete
        .try_reserve(chunks.len())
        .map_err(|error| format!("phase-2 GPU complete-row reserve failed: {error}"))?;
    for shard in shards {
        let shard = shard?;
        let rows = shard.chunks.len();
        let admission = catalog.scan_admission_chunks(backend, &chunks[shard.chunks])?;
        append_phase2_gpu_admission(&mut merged, admission, rows)?;
    }
    Ok(merged)
}

pub(super) fn scan_phase2_gpu_refs_sharded(
    catalog: &Phase2GpuDfaCatalog,
    backend: &dyn vyre::VyreBackend,
    chunks: &[&keyhog_core::Chunk],
) -> std::result::Result<Phase2GpuDfaAdmission, String> {
    let byte_limit = region_presence_batch_byte_limit(backend.id());
    if region_presence_ref_batch_len(chunks)? <= byte_limit {
        return catalog.scan_admission_refs(backend, chunks);
    }
    let shards = region_presence_ref_shards(chunks, byte_limit)?;
    let mut merged = Phase2GpuDfaAdmission {
        admitted: Vec::new(),
        complete: Vec::new(),
        matches_seen: 0,
    };
    merged
        .admitted
        .try_reserve(chunks.len())
        .map_err(|error| format!("phase-2 GPU admitted-row reserve failed: {error}"))?;
    merged
        .complete
        .try_reserve(chunks.len())
        .map_err(|error| format!("phase-2 GPU complete-row reserve failed: {error}"))?;
    for shard in shards {
        let shard = shard?;
        let rows = shard.chunks.len();
        let admission = catalog.scan_admission_refs(backend, &chunks[shard.chunks])?;
        append_phase2_gpu_admission(&mut merged, admission, rows)?;
    }
    Ok(merged)
}
