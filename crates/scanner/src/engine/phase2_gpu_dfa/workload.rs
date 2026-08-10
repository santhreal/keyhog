//! Phase-2 GPU admission workload shaping and full-batch expansion.

pub(crate) struct Phase2GpuDfaAdmission {
    pub(crate) admitted: Vec<bool>,
    /// Per-region proof that a negative admission bit covered every
    /// prefixless always-active pattern relevant to that region's byte class.
    pub(crate) complete: Vec<bool>,
    /// Distinct (region, shard-local pattern) admission bits observed. This is
    /// telemetry only; exact extraction remains owned by the shared CPU tail.
    pub(crate) matches_seen: usize,
    /// Concatenated shard-local candidate words for each region. Word order is
    /// deterministic catalog shard order; extraction remains on the CPU.
    pub(crate) candidate_bits: Vec<u32>,
    pub(crate) candidate_words_per_region: usize,
    /// Bit-position to production phase-2 index. Padding bits use `u32::MAX`.
    pub(crate) candidate_phase2_indices: Vec<u32>,
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
) -> Phase2GpuAdmissionWorkload<'a> {
    build_phase2_gpu_admission_workload_filtered(chunks, |_, _| true)
}

pub(in crate::engine) fn build_phase2_gpu_admission_workload_filtered<'a>(
    chunks: &'a [keyhog_core::Chunk],
    include_chunk: impl Fn(usize, &'a keyhog_core::Chunk) -> bool,
) -> Phase2GpuAdmissionWorkload<'a> {
    let mut first_excluded_index = None;
    let mut indices = Vec::new();
    let mut selected_chunks = Vec::new();

    for (idx, chunk) in chunks.iter().enumerate() {
        if include_chunk(idx, chunk) {
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
    let mut complete = vec![false; full_len];
    let candidate_len_matches = subset
        .candidate_words_per_region
        .checked_mul(workload_indices.len())
        .is_some_and(|length| length == subset.candidate_bits.len());
    let candidate_map_matches = subset
        .candidate_words_per_region
        .checked_mul(u32::BITS as usize)
        .is_some_and(|length| length == subset.candidate_phase2_indices.len());
    let indices_in_range = workload_indices.iter().all(|&index| index < full_len);
    let candidate_full_len = subset.candidate_words_per_region.checked_mul(full_len);
    let length_mismatch = subset.admitted.len() != workload_indices.len()
        || subset.complete.len() != workload_indices.len()
        || !indices_in_range
        || candidate_full_len.is_none()
        || !candidate_len_matches
        || !candidate_map_matches;
    for (&is_admitted, &full_idx) in subset.admitted.iter().zip(workload_indices.iter()) {
        if is_admitted {
            if let Some(slot) = admitted.get_mut(full_idx) {
                *slot = true;
            }
        }
    }
    for (&is_complete, &full_idx) in subset.complete.iter().zip(workload_indices.iter()) {
        if is_complete {
            if let Some(slot) = complete.get_mut(full_idx) {
                *slot = true;
            }
        }
    }
    let candidate_words_per_region = subset.candidate_words_per_region;
    let mut candidate_bits = if length_mismatch {
        Vec::new()
    } else {
        vec![0; candidate_full_len.expect("validated candidate length")]
    };
    if !length_mismatch {
        for (subset_row, &full_idx) in workload_indices.iter().enumerate() {
            let source_start = subset_row * candidate_words_per_region;
            let destination_start = full_idx * candidate_words_per_region;
            candidate_bits[destination_start..destination_start + candidate_words_per_region]
                .copy_from_slice(
                    &subset.candidate_bits[source_start..source_start + candidate_words_per_region],
                );
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
        complete: if length_mismatch {
            vec![false; full_len]
        } else {
            complete
        },
        matches_seen: subset.matches_seen,
        candidate_bits: if length_mismatch {
            Vec::new()
        } else {
            candidate_bits
        },
        candidate_words_per_region: if length_mismatch {
            0
        } else {
            candidate_words_per_region
        },
        candidate_phase2_indices: if length_mismatch {
            Vec::new()
        } else {
            subset.candidate_phase2_indices
        },
    }
}
