//! Candidate discovery and prioritization for phase-2 GPU regex-DFA admission.

use super::super::phase2::gate_prefix_literals;
use crate::types::CompiledPattern;
use std::collections::HashSet;

pub(super) fn prefixless_always_active_candidates(
    phase2_patterns: &[(CompiledPattern, Vec<String>)],
    always_active_indices: &[usize],
) -> Vec<usize> {
    let mut candidates = Vec::with_capacity(always_active_indices.len());
    for &idx in always_active_indices {
        let Some((pattern, _)) = phase2_patterns.get(idx) else {
            tracing::warn!(
                target: "keyhog::gpu",
                index = idx,
                patterns = phase2_patterns.len(),
                "phase-2 GPU regex-DFA admission received out-of-range always-active pattern index; invalid index ignored and CPU admission remains authoritative"
            );
            continue;
        };
        if gate_prefix_literals(pattern.regex.as_str()).is_none() {
            candidates.push(idx);
        }
    }
    candidates
}

pub(super) fn prioritized_phase2_gpu_dfa_candidates(
    phase2_patterns: &[(CompiledPattern, Vec<String>)],
    candidates: &[usize],
    max_candidates: usize,
) -> Vec<usize> {
    let candidates = valid_phase2_gpu_dfa_candidates(phase2_patterns, candidates);
    let mut selected = Vec::with_capacity(candidates.len().min(max_candidates));
    let mut selected_indices = HashSet::new();
    let mut base_detectors = HashSet::new();
    let mut homoglyph_detectors = HashSet::new();

    append_phase2_gpu_dfa_candidates(
        phase2_patterns,
        &candidates,
        max_candidates,
        &mut selected,
        &mut selected_indices,
        |pattern| !pattern.homoglyph_variant && base_detectors.insert(pattern.detector_index),
    );
    append_phase2_gpu_dfa_candidates(
        phase2_patterns,
        &candidates,
        max_candidates,
        &mut selected,
        &mut selected_indices,
        |pattern| !pattern.homoglyph_variant,
    );
    append_phase2_gpu_dfa_candidates(
        phase2_patterns,
        &candidates,
        max_candidates,
        &mut selected,
        &mut selected_indices,
        |pattern| pattern.homoglyph_variant && homoglyph_detectors.insert(pattern.detector_index),
    );
    append_phase2_gpu_dfa_candidates(
        phase2_patterns,
        &candidates,
        max_candidates,
        &mut selected,
        &mut selected_indices,
        |_| true,
    );

    selected
}

pub(super) fn valid_phase2_gpu_dfa_candidates(
    phase2_patterns: &[(CompiledPattern, Vec<String>)],
    candidates: &[usize],
) -> Vec<usize> {
    let mut valid = Vec::with_capacity(candidates.len());
    for &idx in candidates {
        if phase2_patterns.get(idx).is_some() {
            valid.push(idx);
        } else {
            tracing::warn!(
                target: "keyhog::gpu",
                index = idx,
                patterns = phase2_patterns.len(),
                "phase-2 GPU regex-DFA candidate selection received out-of-range pattern index; invalid index ignored before prioritization"
            );
        }
    }
    valid
}

fn append_phase2_gpu_dfa_candidates<F>(
    phase2_patterns: &[(CompiledPattern, Vec<String>)],
    candidates: &[usize],
    max_candidates: usize,
    selected: &mut Vec<usize>,
    selected_indices: &mut HashSet<usize>,
    mut accepts: F,
) where
    F: FnMut(&CompiledPattern) -> bool,
{
    if selected.len() >= max_candidates {
        return;
    }
    for &idx in candidates {
        if selected.len() >= max_candidates {
            return;
        }
        let Some((pattern, _)) = phase2_patterns.get(idx) else {
            tracing::warn!(
                target: "keyhog::gpu",
                index = idx,
                patterns = phase2_patterns.len(),
                "phase-2 GPU regex-DFA candidate append received out-of-range pattern index; invalid index ignored before selection"
            );
            continue;
        };
        if selected_indices.contains(&idx) || !accepts(pattern) {
            continue;
        }
        selected.push(idx);
        selected_indices.insert(idx);
    }
}
