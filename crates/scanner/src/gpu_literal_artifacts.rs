//! Offline GPU literal artifact compiler.
//!
//! This module is intentionally free of GPU device acquisition. It derives the
//! exact literal rows the runtime scanner would feed to VYRE and serializes
//! them with VYRE's own wire format, so install/release calibration can persist
//! matcher artifacts without reimplementing scanner compile semantics.

use crate::compiler::{
    build_compile_state, build_gpu_literals, build_phase2_keyword_index,
    phase2_always_active_indices, validate_compiled_pattern_detector_indices,
};
use crate::engine::{phase2_anchor, phase2_generic, scan_postprocess};
use crate::error::{Result, ScanError};
use crate::gpu_matcher_cache as gpu_cache;
use crate::scanner_config::ScannerTuningConfig;
use keyhog_core::{CompiledArtifactClass, DetectorSpec};

/// The compiled artifact class for GPU literal match sets.
pub const ARTIFACT_CLASS: CompiledArtifactClass = CompiledArtifactClass::GpuLiteralSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use vyre::scan::GpuLiteralSet;

static INSTALL_COMPILED_INVOCATIONS: AtomicUsize = AtomicUsize::new(0);
static RUNTIME_COMPILER_INVOCATIONS: AtomicUsize = AtomicUsize::new(0);

#[cfg(feature = "gpu")]
pub(crate) struct InstalledGpuLiteralArtifact {
    pub(crate) matcher: GpuLiteralSet,
    pub(crate) cache_key: Arc<str>,
    pub(crate) pattern_count: usize,
    pub(crate) max_literal_len: usize,
}

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

impl GpuLiteralArtifact {
    /// The compiled artifact class for this artifact.
    pub const ARTIFACT_CLASS: CompiledArtifactClass = CompiledArtifactClass::GpuLiteralSet;

    /// The compiled artifact class for this artifact.
    pub const fn artifact_class(&self) -> CompiledArtifactClass {
        CompiledArtifactClass::GpuLiteralSet
    }
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
#[cfg(feature = "gpu")]

pub(crate) fn install_compiled_gpu_literal_artifact(
    cache_key: String,
    pattern_count: u32,
    matcher_bytes: &[u8],
) -> Result<InstalledGpuLiteralArtifact> {
    INSTALL_COMPILED_INVOCATIONS.fetch_add(1, Ordering::Relaxed);
    keyhog_profile::add_counter(keyhog_profile::CounterId::GpuCompileCalls, 1);
    if !cache_key.starts_with("lit-ci-") {
        return Err(ScanError::Gpu(format!(
            "packed GPU matcher cache key {cache_key:?} is not a fused case-insensitive matcher key"
        )));
    }
    let matcher = GpuLiteralSet::from_bytes(matcher_bytes).map_err(|error| {
        ScanError::Gpu(format!(
            "failed to install the packed VYRE GPU matcher {cache_key}: {error}. Fix: reinstall and recalibrate the execution pack."
        ))
    })?;
    if !matcher.case_insensitive {
        return Err(ScanError::Gpu(format!(
            "packed VYRE GPU matcher {cache_key} is not case-insensitive; reinstall and recalibrate"
        )));
    }
    let pattern_count = usize::try_from(pattern_count).map_err(|_| {
        ScanError::Gpu("packed VYRE matcher pattern count does not fit this target".into())
    })?;
    if matcher.pattern_lengths.len() != pattern_count {
        return Err(ScanError::Gpu(format!(
            "packed VYRE GPU matcher {cache_key} declares {pattern_count} patterns but contains {}; reinstall and recalibrate",
            matcher.pattern_lengths.len()
        )));
    }
    let max_literal_len = matcher
        .pattern_lengths
        .iter()
        .copied()
        .max()
        // LAW10: failed checked conversion reaches ok_or_else and rejects the artifact; no literal length is substituted.
        .and_then(|length| usize::try_from(length).ok())
        .ok_or_else(|| {
            ScanError::Gpu(format!(
                "packed VYRE GPU matcher {cache_key} contains no valid literal lengths; reinstall and recalibrate"
            ))
        })?;
    keyhog_profile::record_compile_surface_load(keyhog_profile::CompileSurfaceId::GpuLiterals);
    Ok(InstalledGpuLiteralArtifact {
        matcher,
        cache_key: cache_key.into(),
        pattern_count,
        max_literal_len,
    })
}

pub(crate) fn record_runtime_gpu_literal_compiler_invocation() {
    RUNTIME_COMPILER_INVOCATIONS.fetch_add(1, Ordering::Relaxed);
    keyhog_profile::add_counter(keyhog_profile::CounterId::GpuCompileCalls, 1);
    keyhog_profile::record_compile_surface_invocation(
        keyhog_profile::CompileSurfaceId::GpuLiterals,
    );
}

#[doc(hidden)]
pub fn install_compiled_gpu_literal_invocations() -> usize {
    INSTALL_COMPILED_INVOCATIONS.load(Ordering::Relaxed)
}

#[doc(hidden)]
pub fn runtime_gpu_literal_compiler_invocations() -> usize {
    RUNTIME_COMPILER_INVOCATIONS.load(Ordering::Relaxed)
}

#[doc(hidden)]
pub fn gpu_literal_plan_compiler_invocations() -> usize {
    crate::compiler::compiler_compile::build_gpu_literals_invocations()
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
    keyhog_profile::record_compile_surface_invocation(
        keyhog_profile::CompileSurfaceId::GpuLiterals,
    );
    let state = build_compile_state(detectors)?;
    validate_compiled_pattern_detector_indices(
        &state.ac_map,
        &state.phase2_patterns,
        detectors.len(),
    )?;
    let (_, _, phase2_keywords) = build_phase2_keyword_index(&state.phase2_patterns);
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
    let generic_keyword_plan = if detectors.iter().any(DetectorSpec::owns_entropy_policy) {
        Some(
            phase2_generic::keywords::GenericAssignmentKeywordPlan::compile(detectors)
                .map_err(crate::error::ScanError::Config)?,
        )
    } else {
        None
    };

    Ok(GpuLiteralArtifacts {
        literal: serialize_literal_rows(
            "lit-ci",
            build_gpu_literals(
                state.ac_literals.iter().map(String::as_bytes),
                phase2_keywords.iter().map(|keyword| keyword.as_bytes()),
                phase2_always_anchor_literals.iter().map(String::as_bytes),
                confirmed_anchor_literals.iter().map(String::as_bytes),
                generic_keyword_plan
                    .iter()
                    .flat_map(|plan| plan.stem_literals())
                    .map(str::as_bytes),
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
        GpuLiteralSet::compile_case_insensitive(&literal_refs)
    }))
    .map_err(|panic| {
        let detail = crate::error::panic_payload_detail(panic);
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
