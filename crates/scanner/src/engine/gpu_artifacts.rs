//! Offline GPU literal artifact compiler.
//!
//! This module is intentionally free of GPU device acquisition. It derives the
//! exact literal rows the runtime scanner would feed to Vyre and serializes
//! them with Vyre's own wire format, so install/release calibration can persist
//! matcher artifacts without reimplementing scanner compile semantics.

use super::{gpu_cache, phase2_anchor};
use crate::compiler::{
    build_compile_state, build_gpu_literals, build_phase2_keyword_ac,
};
use crate::error::{Result, ScanError};
use crate::scanner_config::ScannerTuningConfig;
use keyhog_core::DetectorSpec;
use std::sync::Arc;
use vyre_libs::scan::{GpuLiteralSet, MatchEngineCache};

/// Serialized Vyre literal matcher plus the cache identity used by runtime.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GpuLiteralArtifact {
    /// Runtime cache filename stem, including Keyhog's matcher prefix.
    pub cache_key: String,
    /// Number of literal rows compiled into the matcher.
    pub pattern_count: usize,
    /// Vyre `GpuLiteralSet` wire bytes.
    pub bytes: Vec<u8>,
    /// Vyre wire magic stamped into `bytes`.
    pub wire_magic: [u8; 4],
    /// Vyre wire version stamped into `bytes`.
    pub wire_version: u32,
}

/// The runtime GPU presence matcher artifacts derivable without a GPU device.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct GpuLiteralArtifacts {
    /// Main phase-1 region-presence matcher.
    pub literal: Option<GpuLiteralArtifact>,
    /// Retired positioned-matcher slot, kept for source compatibility.
    ///
    /// Runtime removed the redundant second GPU literal pass in v0.5.40; the
    /// artifact compiler therefore returns `None` and performs no positioned
    /// matcher compilation. Consumers should ignore this field.
    pub positioned_literal: Option<GpuLiteralArtifact>,
}

/// Compile GPU literal artifacts using shipped-default scanner tuning.
pub fn compile_gpu_literal_artifacts_default(
    detectors: &[DetectorSpec],
) -> Result<GpuLiteralArtifacts> {
    compile_gpu_literal_artifacts(detectors, &ScannerTuningConfig::default())
}

/// Compile the exact Vyre literal artifacts for a detector set and tuning.
///
/// This does not probe hardware and does not initialize wgpu/CUDA. It does run
/// the scanner compiler because literal rows depend on the same routing
/// decisions the runtime scanner makes, including the Hyperscan-unsupported
/// reroute into phase 2 when the `simd` feature is enabled.
pub fn compile_gpu_literal_artifacts(
    detectors: &[DetectorSpec],
    tuning_config: &ScannerTuningConfig,
) -> Result<GpuLiteralArtifacts> {
    let mut state = build_compile_state(detectors)?;
    reroute_hyperscan_unsupported_patterns(&mut state, detectors, tuning_config);

    let (_, _, phase2_keywords) = build_phase2_keyword_ac(&state.phase2_patterns);
    let phase2_always_active_indices = phase2_always_active_indices(&state.phase2_patterns);
    let phase2_anchor_index = phase2_anchor::Phase2AnchorIndex::build(
        &state.phase2_patterns,
        &phase2_always_active_indices,
    );
    let phase2_always_anchor_literals = phase2_anchor_index
        .as_ref()
        .map_or(&[] as &[String], |index| index.always_anchor_literals());

    Ok(GpuLiteralArtifacts {
        literal: serialize_literal_rows(
            "lit",
            build_gpu_literals(
                &state.ac_literals,
                &phase2_keywords,
                phase2_always_anchor_literals,
            ),
        )?,
        positioned_literal: None,
    })
}

pub(super) fn phase2_always_active_indices(
    phase2_patterns: &[(crate::types::CompiledPattern, Vec<String>)],
) -> Vec<usize> {
    phase2_patterns
        .iter()
        .enumerate()
        // Mirrors `compiler::build_phase2_keyword_ac`'s 4-char floor. The
        // experimental 3-char floor measured a net F1 regression on
        // SecretBench-medium, so both checks stay at 4.
        .filter_map(|(index, (_, keywords))| {
            (!keywords.iter().any(|keyword| keyword.len() >= 4)).then_some(index)
        })
        .collect()
}

pub(super) fn append_hyperscan_unsupported_patterns(
    state: &mut crate::compiler::compiler_build::CompileState,
    detectors: &[DetectorSpec],
    unsupported_ac: impl IntoIterator<Item = usize>,
) {
    for ac_idx in unsupported_ac {
        let pattern = state.ac_map[ac_idx].clone();
        let keywords = detectors[pattern.detector_index].keywords.clone();
        state.phase2_patterns.push((pattern, keywords));
    }
}

#[cfg(feature = "simd")]
fn reroute_hyperscan_unsupported_patterns(
    state: &mut crate::compiler::compiler_build::CompileState,
    detectors: &[DetectorSpec],
    tuning_config: &ScannerTuningConfig,
) {
    if let Some((_scanner, _index_map, unsupported_ac)) =
        super::build_simd_scanner(&state.ac_map, tuning_config)
    {
        append_hyperscan_unsupported_patterns(state, detectors, unsupported_ac);
    }
}

#[cfg(not(feature = "simd"))]
fn reroute_hyperscan_unsupported_patterns(
    _state: &mut crate::compiler::compiler_build::CompileState,
    _detectors: &[DetectorSpec],
    _tuning_config: &ScannerTuningConfig,
) {
}

fn serialize_literal_rows(
    cache_prefix: &'static str,
    rows: Option<Arc<Vec<Vec<u8>>>>,
) -> Result<Option<GpuLiteralArtifact>> {
    let Some(rows) = rows else {
        return Ok(None);
    };
    let literal_refs: Vec<&[u8]> = rows.iter().map(Vec::as_slice).collect();
    let cache_key = format!(
        "{cache_prefix}-{}",
        gpu_cache::gpu_matcher_cache_key(&literal_refs)
    );
    let pattern_count = literal_refs.len();
    let matcher = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        GpuLiteralSet::compile(&literal_refs)
    }))
    .map_err(|panic| {
        let detail = if let Some(message) = panic.downcast_ref::<String>() {
            message.as_str()
        } else if let Some(message) = panic.downcast_ref::<&'static str>() {
            message
        } else {
            "non-string panic payload"
        };
        ScanError::Gpu(format!(
            "GPU literal artifact compile panicked for cache prefix {cache_prefix} with {pattern_count} patterns: {detail}. Fix: reduce literal rows, increase Vyre's DFA budget, or shard the literal set."
        ))
    })?;
    let bytes = matcher.to_bytes().map_err(|error| {
        ScanError::Gpu(format!(
            "failed to serialize GPU literal artifact for cache prefix {cache_prefix} with {pattern_count} patterns: {error}. Fix: upgrade Vyre or rebuild the artifact with a compatible keyhog binary."
        ))
    })?;

    Ok(Some(GpuLiteralArtifact {
        cache_key,
        pattern_count,
        bytes,
        wire_magic: GpuLiteralSet::WIRE_MAGIC,
        wire_version: GpuLiteralSet::WIRE_VERSION,
    }))
}
