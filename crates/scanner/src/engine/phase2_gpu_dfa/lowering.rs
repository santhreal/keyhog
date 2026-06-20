//! Regex-DFA source lowering and shard construction for phase-2 GPU admission.

use super::{Phase2GpuDfaShard, PHASE2_GPU_DFA_MAX_MATCHES, PHASE2_GPU_DFA_MAX_STATES};
use crate::types::CompiledPattern;
use std::borrow::Cow;

pub(super) fn build_shards_recursive(
    phase2_patterns: &[(CompiledPattern, Vec<String>)],
    indices: &[usize],
    use_subgroup_coalesce: bool,
    shards: &mut Vec<Phase2GpuDfaShard>,
    uncovered_patterns: &mut usize,
) {
    if indices.is_empty() {
        return;
    }
    match build_shard(phase2_patterns, indices, use_subgroup_coalesce) {
        Ok(shard) => {
            shards.push(shard);
        }
        Err(error) if indices.len() > 1 => {
            let mid = indices.len() / 2;
            build_shards_recursive(
                phase2_patterns,
                &indices[..mid],
                use_subgroup_coalesce,
                shards,
                uncovered_patterns,
            );
            build_shards_recursive(
                phase2_patterns,
                &indices[mid..],
                use_subgroup_coalesce,
                shards,
                uncovered_patterns,
            );
            tracing::debug!(
                target: "keyhog::gpu",
                patterns = indices.len(),
                %error,
                "phase-2 GPU regex-DFA shard split after compile failure"
            );
        }
        Err(error) => {
            *uncovered_patterns = uncovered_patterns.saturating_add(indices.len());
            tracing::warn!(
                target: "keyhog::gpu",
                phase2_index = indices[0],
                %error,
                "phase-2 prefixless pattern could not lower to GPU regex-DFA; CPU admission remains authoritative for it"
            );
        }
    }
}

fn build_shard(
    phase2_patterns: &[(CompiledPattern, Vec<String>)],
    indices: &[usize],
    use_subgroup_coalesce: bool,
) -> std::result::Result<Phase2GpuDfaShard, String> {
    let mut sources = Vec::with_capacity(indices.len());
    for &idx in indices {
        let (pattern, _) = phase2_patterns
            .get(idx)
            .ok_or_else(|| format!("phase-2 index {idx} is out of range"))?;
        sources.push(regex_dfa_source_for_pattern(pattern));
    }
    let source_refs: Vec<&str> = sources.iter().map(|source| source.as_ref()).collect();
    let mut pipeline = vyre_libs::scan::build_regex_dfa_unanchored(
        &source_refs,
        PHASE2_GPU_DFA_MAX_MATCHES,
        PHASE2_GPU_DFA_MAX_STATES,
    )
    .map_err(|error| error.to_string())?;
    if !use_subgroup_coalesce {
        pipeline.program = vyre_libs::scan::classic_ac::try_build_ac_bounded_ranges_program_ext(
            &pipeline.dfa,
            u32::try_from(source_refs.len()).map_err(|error| {
                format!(
                    "phase-2 GPU regex-DFA shard pattern count {} exceeds u32 ABI: {error}",
                    source_refs.len()
                )
            })?,
            PHASE2_GPU_DFA_MAX_MATCHES,
            false,
        )
        .map_err(|error| {
            format!("phase-2 GPU regex-DFA CUDA-compatible program build failed: {error}")
        })?;
    }
    Ok(Phase2GpuDfaShard {
        pipeline,
        phase2_indices: indices.to_vec(),
    })
}

pub(super) fn regex_dfa_source_for_pattern(pattern: &CompiledPattern) -> Cow<'_, str> {
    let source = pattern.regex.as_str();
    if pattern.regex.is_case_insensitive() {
        let mut wrapped = String::with_capacity(source.len() + "(?i:)".len());
        wrapped.push_str("(?i:");
        wrapped.push_str(source);
        wrapped.push(')');
        Cow::Owned(wrapped)
    } else {
        Cow::Borrowed(source)
    }
}
