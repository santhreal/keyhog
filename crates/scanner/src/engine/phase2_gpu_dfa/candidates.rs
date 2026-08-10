//! Candidate discovery for phase-2 GPU regex-DFA admission.

use super::super::phase2::gate_prefix_literals;
use super::lowering::CpuRequiredReason;
use crate::types::CompiledPattern;

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

/// Complete nonredundant prefixless always-active set for a row that provably
/// carries no confusable glyph.
///
/// A compiler-generated homoglyph variant is paired with a base detector
/// prefix in phase 1. With no confusable present, any match of the variant
/// necessarily contains that base prefix, so phase one already admits the base
/// detector. The shared CPU and Hyperscan paths use the same invariant through
/// `homoglyph_ascii_skip`.
///
/// The variants cannot simply be added to the covered set instead: a single
/// homoglyph variant needs more than 1024 NFA states and vyre's GPU regex
/// pipeline caps a pipeline at `LANES * 32 == 1024`, so they do not lower.
pub(super) fn ascii_phase2_gpu_dfa_candidates(
    phase2_patterns: &[(CompiledPattern, Vec<String>)],
    candidates: &[usize],
) -> Vec<usize> {
    candidates
        .iter()
        .copied()
        .filter(|&idx| !phase2_patterns[idx].0.homoglyph_variant)
        .collect()
}

pub(super) fn cpu_required_reason(
    pattern: &CompiledPattern,
    keywords: &[String],
    always_active: bool,
) -> Option<CpuRequiredReason> {
    if !always_active {
        return Some(CpuRequiredReason::KeywordGated);
    }
    if gate_prefix_literals(pattern.regex.as_str()).is_some() {
        return Some(CpuRequiredReason::GatePrefixed);
    }
    if pattern.homoglyph_variant {
        return Some(CpuRequiredReason::AsciiHomoglyphRedundant);
    }
    debug_assert!(!keywords.iter().any(|keyword| keyword.len() >= 4));
    None
}
