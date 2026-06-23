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
        let (pattern, _) = &phase2_patterns[idx];
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
    let mut selected = Vec::with_capacity(candidates.len().min(max_candidates));
    let mut selected_indices = HashSet::new();
    let mut base_detectors = HashSet::new();
    let mut homoglyph_detectors = HashSet::new();

    append_phase2_gpu_dfa_candidates(
        phase2_patterns,
        candidates,
        max_candidates,
        &mut selected,
        &mut selected_indices,
        |pattern| !pattern.homoglyph_variant && base_detectors.insert(pattern.detector_index),
    );
    append_phase2_gpu_dfa_candidates(
        phase2_patterns,
        candidates,
        max_candidates,
        &mut selected,
        &mut selected_indices,
        |pattern| !pattern.homoglyph_variant,
    );
    append_phase2_gpu_dfa_candidates(
        phase2_patterns,
        candidates,
        max_candidates,
        &mut selected,
        &mut selected_indices,
        |pattern| pattern.homoglyph_variant && homoglyph_detectors.insert(pattern.detector_index),
    );
    append_phase2_gpu_dfa_candidates(
        phase2_patterns,
        candidates,
        max_candidates,
        &mut selected,
        &mut selected_indices,
        |_| true,
    );

    selected
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
        let (pattern, _) = &phase2_patterns[idx];
        if selected_indices.contains(&idx) || !accepts(pattern) {
            continue;
        }
        selected.push(idx);
        selected_indices.insert(idx);
    }
}
