//! Phase-2 GPU admission workload shaping and full-batch expansion.

pub(crate) struct Phase2GpuDfaAdmission {
    pub(crate) admitted: Vec<bool>,
    pub(crate) complete: bool,
    pub(crate) matches_seen: usize,
}

pub(in crate::engine) enum Phase2GpuAdmissionWorkload<'a> {
    Empty,
    Full {
        chunks: &'a [keyhog_core::Chunk],
    },
    Subset {
        indices: Vec<usize>,
        chunks: Vec<&'a keyhog_core::Chunk>,
        full_len: usize,
    },
}

fn trigger_has_bits(trigger: Option<&[u64]>) -> bool {
    trigger.is_some_and(|bits| bits.iter().any(|&word| word != 0))
}

pub(in crate::engine) fn validate_phase2_gpu_trigger_rows(
    chunk_count: usize,
    trigger_count: usize,
) -> std::result::Result<(), String> {
    if chunk_count == trigger_count {
        return Ok(());
    }
    Err(format!(
        "coalesced GPU region presence produced {trigger_count} trigger row(s) for {chunk_count} chunk(s); refusing to run mismatched phase-2 admission"
    ))
}

#[cfg(test)]
pub(in crate::engine) fn build_phase2_gpu_admission_workload<'a>(
    chunks: &'a [keyhog_core::Chunk],
    triggers: &[Option<Vec<u64>>],
) -> Phase2GpuAdmissionWorkload<'a> {
    build_phase2_gpu_admission_workload_filtered(chunks, triggers, |_, _| true)
}

pub(in crate::engine) fn build_phase2_gpu_admission_workload_filtered<'a>(
    chunks: &'a [keyhog_core::Chunk],
    triggers: &[Option<Vec<u64>>],
    include_no_trigger_chunk: impl Fn(usize, &'a keyhog_core::Chunk) -> bool,
) -> Phase2GpuAdmissionWorkload<'a> {
    let mut first_triggered_index = None;
    let mut first_excluded_index = None;
    let mut indices = Vec::new();
    let mut selected_chunks = Vec::new();

    for (idx, chunk) in chunks.iter().enumerate() {
        let has_trigger = trigger_has_bits(
            triggers
                .get(idx)
                .and_then(|trigger| trigger.as_ref().map(Vec::as_slice)),
        );
        if has_trigger && first_triggered_index.is_none() {
            first_triggered_index = Some(idx);
        }
        if !has_trigger && include_no_trigger_chunk(idx, chunk) {
            if first_excluded_index.is_none() {
                continue;
            }
            indices.push(idx);
            selected_chunks.push(chunk);
            continue;
        }

        if first_excluded_index.is_none() {
            first_excluded_index = Some(idx);
            let remaining = chunks.len().saturating_sub(idx);
            indices = Vec::with_capacity(idx.saturating_add(remaining));
            selected_chunks = Vec::with_capacity(idx.saturating_add(remaining));
            for (prefix_idx, prefix_chunk) in chunks[..idx].iter().enumerate() {
                indices.push(prefix_idx);
                selected_chunks.push(prefix_chunk);
            }
        }
    }

    debug_assert!(first_triggered_index.is_none() || first_excluded_index.is_some());

    match (first_excluded_index, indices.is_empty()) {
        (None, _) => Phase2GpuAdmissionWorkload::Full { chunks },
        (Some(_), true) => Phase2GpuAdmissionWorkload::Empty,
        (Some(_), false) => Phase2GpuAdmissionWorkload::Subset {
            indices,
            chunks: selected_chunks,
            full_len: chunks.len(),
        },
    }
}

pub(in crate::engine) fn expand_phase2_gpu_admission(
    subset: Phase2GpuDfaAdmission,
    workload_indices: &[usize],
    full_len: usize,
) -> Phase2GpuDfaAdmission {
    let mut admitted = vec![false; full_len];
    let length_mismatch = subset.admitted.len() != workload_indices.len();
    for (&is_admitted, &full_idx) in subset.admitted.iter().zip(workload_indices.iter()) {
        if is_admitted {
            if let Some(slot) = admitted.get_mut(full_idx) {
                *slot = true;
            }
        }
    }
    if length_mismatch {
        tracing::warn!(
            target: "keyhog::gpu",
            subset_len = subset.admitted.len(),
            workload_len = workload_indices.len(),
            "phase-2 GPU regex-DFA admission length mismatch; CPU admission remains authoritative for missing slots"
        );
    }
    Phase2GpuDfaAdmission {
        admitted,
        complete: subset.complete && !length_mismatch,
        matches_seen: subset.matches_seen,
    }
}
