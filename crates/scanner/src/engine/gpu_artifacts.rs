//! Offline GPU literal artifact compiler.
//!
//! This module is intentionally free of GPU device acquisition. It derives the
//! exact literal rows the runtime scanner would feed to VYRE and serializes
//! them with VYRE's own wire format, so install/release calibration can persist
//! matcher artifacts without reimplementing scanner compile semantics.

use super::{gpu_cache, phase2_anchor, phase2_generic, scan_postprocess};
use crate::compiler::{
    build_compile_state, build_gpu_literals, build_phase2_keyword_ac, phase2_always_active_indices,
    validate_compiled_pattern_detector_indices,
};
use crate::error::{Result, ScanError};
use crate::scanner_config::ScannerTuningConfig;
use keyhog_core::DetectorSpec;
use std::sync::Arc;
use vyre_libs::scan::GpuLiteralSet;

/// Serialized VYRE literal matcher plus the cache identity used by runtime.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GpuLiteralArtifact {
    /// Runtime cache filename stem, including KeyHog's matcher prefix.
    pub cache_key: String,
    /// Number of literal rows compiled into the matcher.
    pub pattern_count: usize,
    /// VYRE `GpuLiteralSet` wire bytes.
    pub bytes: Vec<u8>,
    /// VYRE wire magic stamped into `bytes`.
    pub wire_magic: [u8; 4],
    /// VYRE wire version stamped into `bytes`.
    pub wire_version: u32,
}

/// The runtime GPU presence matcher artifacts derivable without a GPU device.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct GpuLiteralArtifacts {
    /// Fused region-presence and positioned-evidence matcher.
    pub literal: Option<GpuLiteralArtifact>,
    /// Legacy separate positioned matcher. New artifacts leave this absent
    /// because positioned evidence is compiled into `literal`.
    pub positioned_literal: Option<GpuLiteralArtifact>,
}

/// Canonical runtime directory for serialized GPU literal matcher artifacts.
///
/// Installers use this accessor instead of duplicating the cache-layout
/// contract owned by the scanner.
pub fn gpu_literal_artifact_cache_dir() -> Result<std::path::PathBuf> {
    gpu_cache::gpu_matcher_cache_dir().map_err(|error| ScanError::Gpu(error.to_string()))
}

/// Compile GPU literal artifacts from the canonical detector plan.
pub fn compile_gpu_literal_artifacts_default(
    detectors: &[DetectorSpec],
) -> Result<GpuLiteralArtifacts> {
    compile_gpu_literal_artifact_plan(detectors)
}

/// Compatibility entry point for callers that supplied Hyperscan tuning.
/// GPU literal artifacts now depend only on the canonical detector plan.
pub fn compile_gpu_literal_artifacts(
    detectors: &[DetectorSpec],
    _tuning_config: &ScannerTuningConfig,
) -> Result<GpuLiteralArtifacts> {
    compile_gpu_literal_artifact_plan(detectors)
}

/// Compile the exact VYRE literal artifacts for a detector set.
///
/// This does not probe hardware and does not initialize wgpu/CUDA. It does run
/// the scanner compiler because literal rows depend on the same routing
/// decisions the runtime scanner makes. Hyperscan capability does not alter the
/// canonical GPU literal plan.
fn compile_gpu_literal_artifact_plan(detectors: &[DetectorSpec]) -> Result<GpuLiteralArtifacts> {
    let state = build_compile_state(detectors)?;
    validate_compiled_pattern_detector_indices(
        &state.ac_map,
        &state.phase2_patterns,
        detectors.len(),
    )?;
    let (_, _, phase2_keywords) = build_phase2_keyword_ac(&state.phase2_patterns);
    let phase2_always_active_indices = phase2_always_active_indices(&state.phase2_patterns);
    let phase2_anchor_index = phase2_anchor::Phase2AnchorIndex::build(
        &state.phase2_patterns,
        &phase2_always_active_indices,
    );
    let phase2_always_anchor_literals = phase2_anchor_index
        .as_ref()
        .map_or(&[] as &[String], |index| index.always_anchor_literals());

    let confirmed_anchor_index =
        scan_postprocess::confirmed_anchor::ConfirmedAnchorIndex::build(&state.ac_map);
    let confirmed_anchor_literals = confirmed_anchor_index
        .as_ref()
        .map_or(&[] as &[String], |index| index.anchor_literals());
    let generic_keyword_literals = if detectors.iter().any(DetectorSpec::owns_entropy_policy) {
        phase2_generic::keywords::GenericAssignmentKeywordPlan::compile(detectors)
            .map_err(crate::error::ScanError::Config)?
            .stem_literals()
            .map(str::to_owned)
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };

    Ok(GpuLiteralArtifacts {
        literal: serialize_literal_rows(
            "lit",
            build_gpu_literals(
                &state.ac_literals,
                &phase2_keywords,
                phase2_always_anchor_literals,
                confirmed_anchor_literals,
                &generic_keyword_literals,
            ),
        )?,
        positioned_literal: None,
    })
}

fn serialize_literal_rows(
    cache_prefix: &'static str,
    rows: Option<Arc<Vec<Vec<u8>>>>,
) -> Result<Option<GpuLiteralArtifact>> {
    let Some(rows) = rows else {
        return Ok(None);
    };
    let literal_refs: Vec<&[u8]> = rows.iter().map(Vec::as_slice).collect();
    let cache_key = gpu_cache::gpu_matcher_cache_key_with_prefix(cache_prefix, &literal_refs);
    let pattern_count = literal_refs.len();
    let matcher = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        GpuLiteralSet::compile(&literal_refs)
    }))
    .map_err(|panic| {
        let detail = super::gpu_lazy_helpers::catch_unwind_panic_detail(panic);
        ScanError::Gpu(format!(
            "GPU literal artifact compile panicked for cache prefix {cache_prefix} with {pattern_count} patterns: {detail}. Fix: reduce literal rows, increase VYRE's DFA budget, or shard the literal set."
        ))
    })?;
    let bytes = matcher.to_bytes().map_err(|error| {
        ScanError::Gpu(format!(
            "failed to serialize GPU literal artifact for cache prefix {cache_prefix} with {pattern_count} patterns: {error}. Fix: upgrade VYRE or rebuild the artifact with a compatible KeyHog binary."
        ))
    })?;

    // VYRE stamps its literal-set wire envelope header at the front of the
    // serialized blob: a 4-byte magic followed by a little-endian u32 version
    // (`vyre_foundation::serial::envelope` layout). Read the stamped values
    // straight out of `bytes`: that is the single source of truth for what
    // this artifact actually carries and cannot drift from VYRE's private wire
    // constants.
    let (wire_magic, wire_version) = literal_set_wire_header(&bytes).ok_or_else(|| {
        ScanError::Gpu(format!(
            "GPU literal artifact for cache prefix {cache_prefix} serialized to {} bytes, too short for VYRE's 8-byte wire envelope header. Fix: upgrade VYRE or rebuild the artifact with a compatible KeyHog binary.",
            bytes.len()
        ))
    })?;

    Ok(Some(GpuLiteralArtifact {
        cache_key,
        pattern_count,
        bytes,
        wire_magic,
        wire_version,
    }))
}

/// Parse VYRE's literal-set wire envelope header, a `[u8; 4]` magic followed
/// by a little-endian `u32` version, from the front of a serialized
/// `GpuLiteralSet` blob. Returns `None` when the blob is shorter than the
/// 8-byte header (VYRE always writes it, so `None` signals a corrupt/truncated
/// serialization the caller surfaces loudly rather than defaulting).
fn literal_set_wire_header(bytes: &[u8]) -> Option<([u8; 4], u32)> {
    let header = bytes.get(..8)?;
    let magic = [header[0], header[1], header[2], header[3]];
    let version = u32::from_le_bytes([header[4], header[5], header[6], header[7]]);
    Some((magic, version))
}
