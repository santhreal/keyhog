//! Phase-2 GPU admission workload shaping and full-batch expansion.

pub(crate) struct Phase2GpuDfaAdmission {
    pub(crate) admitted: Vec<bool>,
    pub(crate) complete: bool,
    pub(crate) matches_seen: usize,
}

pub(in crate::engine) enum Phase2GpuAdmissionWorkload<'a> {
    Empty {
        full_len: usize,
    },
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

pub(in crate::engine) fn build_phase2_gpu_admission_workload<'a>(
    chunks: &'a [keyhog_core::Chunk],
    triggers: &[Option<Vec<u64>>],
) -> Phase2GpuAdmissionWorkload<'a> {
    let selected_count = chunks
        .iter()
        .enumerate()
        .filter(|(idx, _chunk)| {
            !trigger_has_bits(
                triggers
                    .get(*idx)
                    .and_then(|trigger| trigger.as_ref().map(Vec::as_slice)),
            )
        })
        .count();
    if selected_count == 0 {
        return Phase2GpuAdmissionWorkload::Empty {
            full_len: chunks.len(),
        };
    }
    if selected_count == chunks.len() {
        return Phase2GpuAdmissionWorkload::Full { chunks };
    }

    let mut indices = Vec::with_capacity(selected_count);
    let mut selected_chunks = Vec::with_capacity(selected_count);
    for (idx, chunk) in chunks.iter().enumerate() {
        if trigger_has_bits(
            triggers
                .get(idx)
                .and_then(|trigger| trigger.as_ref().map(Vec::as_slice)),
        ) {
            continue;
        }
        indices.push(idx);
        selected_chunks.push(chunk);
    }
    Phase2GpuAdmissionWorkload::Subset {
        indices,
        chunks: selected_chunks,
        full_len: chunks.len(),
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
