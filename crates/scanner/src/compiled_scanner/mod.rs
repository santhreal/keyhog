//! Scanner construction and lifecycle implementation.
//!
//! The execution engine owns scan stages. This module owns building the
//! immutable scanner, backend acquisition, readiness and runtime inspection,
//! and the public entry methods that dispatch into the engine.

mod compile;
mod compile_helpers;
pub(crate) mod detector_digest;
pub use detector_digest::corpus_route_identity;
mod runtime;
mod types;
mod validation;

pub use types::{
    CompiledDetectorEvidenceRelation, CompiledEvidencePlan, CompiledEvidenceRelation,
    CompiledScannerRuntime, GpuBackendAvailability, GpuBackendCandidateStatus, GpuInitPolicy,
};
pub(crate) use types::{GpuBackendAcquisitionFailure, GpuBackendPeers, SelectedGpuPeer};

/// The compiled artifact class for detector plans.
pub const ARTIFACT_CLASS: keyhog_core::CompiledArtifactClass =
    keyhog_core::CompiledArtifactClass::DetectorPlan;
use crate::compiler::*;
#[cfg(feature = "simd")]
use crate::engine::build_simd_compile_plan;
#[cfg(all(test, feature = "simd"))]
use crate::engine::Phase2HsEngine;
use crate::engine::{
    build_confirmed_suffix_gate_with_hints, derive_pattern_boundary_context, phase2, profile,
    ConfirmedAnchorIndex, CsrU32, Phase1Admission, Phase2AnchorIndex,
};
#[cfg(feature = "gpu")]
use crate::engine::{
    regex_match_byte_upper_bound, GpuResidentLiteralSlot, Phase2GpuDfaCatalogCache,
};
use crate::engine::{CompiledScanner, ScannerBackendState};
use crate::error::Result;
use crate::types::*;
use keyhog_core::{Chunk, DetectorSpec, RawMatch};
use std::sync::{Arc, OnceLock};

#[cfg(test)]
pub(crate) use runtime::Phase2PoolBreakdown;
