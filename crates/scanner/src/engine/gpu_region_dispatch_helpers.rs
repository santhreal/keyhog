use super::gpu_region_batch::{
    region_presence_batch_byte_limit, region_presence_batch_len, region_presence_ref_batch_len,
    region_presence_ref_shards, region_presence_shards,
};
use super::phase2_gpu_dfa::{Phase2GpuDfaAdmission, Phase2GpuDfaCatalog};
use std::ops::Range;

#[cfg(test)]
thread_local! {
    static TEST_PHASE2_FAIL_AFTER_DISPATCHES: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
}

#[cfg(test)]
pub(crate) fn with_test_phase2_dispatch_failure<R>(
    successful_dispatches_before_failure: usize,
    run: impl FnOnce() -> R,
) -> R {
    struct Reset(Option<usize>);
    impl Drop for Reset {
        fn drop(&mut self) {
            TEST_PHASE2_FAIL_AFTER_DISPATCHES.with(|slot| slot.set(self.0));
        }
    }
    let prior = TEST_PHASE2_FAIL_AFTER_DISPATCHES
        .with(|slot| slot.replace(Some(successful_dispatches_before_failure)));
    let _reset = Reset(prior);
    run()
}

#[cfg(test)]
fn injected_phase2_dispatch_failure() -> bool {
    TEST_PHASE2_FAIL_AFTER_DISPATCHES.with(|slot| match slot.get() {
        Some(0) => {
            slot.set(None);
            true
        }
        Some(remaining) => {
            slot.set(Some(remaining - 1));
            false
        }
        None => false,
    })
}

fn scan_phase2_chunks(
    catalog: &Phase2GpuDfaCatalog,
    backend: &std::sync::Arc<dyn vyre::VyreBackend>,
    chunks: &[keyhog_core::Chunk],
) -> Result<Phase2GpuDfaAdmission, String> {
    #[cfg(test)]
    if injected_phase2_dispatch_failure() {
        return Err("injected phase-2 GPU admission dispatch fault".to_string());
    }
    catalog.scan_admission_chunks(backend, chunks)
}

fn scan_phase2_refs(
    catalog: &Phase2GpuDfaCatalog,
    backend: &std::sync::Arc<dyn vyre::VyreBackend>,
    chunks: &[&keyhog_core::Chunk],
) -> Result<Phase2GpuDfaAdmission, String> {
    #[cfg(test)]
    if injected_phase2_dispatch_failure() {
        return Err("injected phase-2 GPU admission dispatch fault".to_string());
    }
    catalog.scan_admission_refs(backend, chunks)
}

pub(super) struct Phase2GpuAdmissionOutcome {
    pub(super) admission: Phase2GpuDfaAdmission,
    pub(super) recovered_rows: Vec<Range<usize>>,
    pub(super) fault: Option<String>,
}

fn recovered_phase2_tail(
    mut admission: Phase2GpuDfaAdmission,
    start: usize,
    total_rows: usize,
    fault: String,
) -> Phase2GpuAdmissionOutcome {
    let remaining = total_rows.saturating_sub(start);
    admission.admitted.resize(total_rows, false);
    admission.complete.resize(total_rows, false);
    Phase2GpuAdmissionOutcome {
        admission,
        recovered_rows: (remaining > 0)
            .then_some(start..total_rows)
            .into_iter()
            .collect(),
        fault: Some(fault),
    }
}

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
    backend: &std::sync::Arc<dyn vyre::VyreBackend>,
    chunks: &[keyhog_core::Chunk],
    recover_dispatch_faults: bool,
) -> std::result::Result<Phase2GpuAdmissionOutcome, String> {
    let byte_limit = region_presence_batch_byte_limit(backend.id());
    if region_presence_batch_len(chunks)? <= byte_limit {
        return match scan_phase2_chunks(catalog, backend, chunks) {
            Ok(admission) => Ok(Phase2GpuAdmissionOutcome {
                admission,
                recovered_rows: Vec::new(),
                fault: None,
            }),
            Err(error) if recover_dispatch_faults => Ok(recovered_phase2_tail(
                Phase2GpuDfaAdmission {
                    admitted: Vec::new(),
                    complete: Vec::new(),
                    matches_seen: 0,
                },
                0,
                chunks.len(),
                error,
            )),
            Err(error) => Err(error),
        };
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
        let start = shard.chunks.start;
        let admission = match scan_phase2_chunks(catalog, backend, &chunks[shard.chunks]) {
            Ok(admission) => admission,
            Err(error) if recover_dispatch_faults => {
                return Ok(recovered_phase2_tail(merged, start, chunks.len(), error));
            }
            Err(error) => return Err(error),
        };
        if let Err(error) = append_phase2_gpu_admission(&mut merged, admission, rows) {
            if recover_dispatch_faults {
                return Ok(recovered_phase2_tail(merged, start, chunks.len(), error));
            }
            return Err(error);
        }
    }
    Ok(Phase2GpuAdmissionOutcome {
        admission: merged,
        recovered_rows: Vec::new(),
        fault: None,
    })
}

pub(super) fn scan_phase2_gpu_refs_sharded(
    catalog: &Phase2GpuDfaCatalog,
    backend: &std::sync::Arc<dyn vyre::VyreBackend>,
    chunks: &[&keyhog_core::Chunk],
    recover_dispatch_faults: bool,
) -> std::result::Result<Phase2GpuAdmissionOutcome, String> {
    let byte_limit = region_presence_batch_byte_limit(backend.id());
    if region_presence_ref_batch_len(chunks)? <= byte_limit {
        return match scan_phase2_refs(catalog, backend, chunks) {
            Ok(admission) => Ok(Phase2GpuAdmissionOutcome {
                admission,
                recovered_rows: Vec::new(),
                fault: None,
            }),
            Err(error) if recover_dispatch_faults => Ok(recovered_phase2_tail(
                Phase2GpuDfaAdmission {
                    admitted: Vec::new(),
                    complete: Vec::new(),
                    matches_seen: 0,
                },
                0,
                chunks.len(),
                error,
            )),
            Err(error) => Err(error),
        };
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
        let start = shard.chunks.start;
        let admission = match scan_phase2_refs(catalog, backend, &chunks[shard.chunks]) {
            Ok(admission) => admission,
            Err(error) if recover_dispatch_faults => {
                return Ok(recovered_phase2_tail(merged, start, chunks.len(), error));
            }
            Err(error) => return Err(error),
        };
        if let Err(error) = append_phase2_gpu_admission(&mut merged, admission, rows) {
            if recover_dispatch_faults {
                return Ok(recovered_phase2_tail(merged, start, chunks.len(), error));
            }
            return Err(error);
        }
    }
    Ok(Phase2GpuAdmissionOutcome {
        admission: merged,
        recovered_rows: Vec::new(),
        fault: None,
    })
}
