//! Regex-DFA source lowering and shard construction for phase-2 GPU admission.

use super::{Phase2GpuDfaShard, PHASE2_GPU_DFA_MAX_STATES};
use crate::types::CompiledPattern;
use std::borrow::Cow;

/// Every shard is a separate dispatch over the SAME haystack, so shard count
/// multiplies GPU work directly. A pool that shatters is not an accelerator,
/// it is a dispatch storm: the caller drops such a catalog and leaves CPU
/// admission authoritative rather than paying for it.
pub(super) const PHASE2_GPU_DFA_MAX_SHARDS: usize = 64;

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
    // One uncovered pattern already forfeits the completeness the caller needs,
    // and splitting past the shard budget only deepens a dispatch storm the
    // caller will refuse anyway. Either way, stop and account the rest.
    if *uncovered_patterns > 0 || shards.len() >= PHASE2_GPU_DFA_MAX_SHARDS {
        *uncovered_patterns = uncovered_patterns.saturating_add(indices.len());
        return;
    }
    // Start with the complete candidate set. A successful compilation gives
    // one dispatch over the haystack; only an actual DFA/state-cap failure may
    // split it into more dispatches.
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
    // Region admission replays an anchored DFA once from each byte origin. An
    // implicit search prefix would rescan earlier bytes from every origin and
    // is only appropriate for the old match-triple materializer.
    let pipeline = vyre_libs::scan::regex_dfa::build_regex_dfa_pipeline_ext(
        &source_refs,
        1,
        PHASE2_GPU_DFA_MAX_STATES,
        use_subgroup_coalesce,
    )
    .map_err(|error| error.to_string())?;
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
