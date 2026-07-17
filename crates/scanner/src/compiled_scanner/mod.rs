//! Scanner construction and lifecycle implementation.
//!
//! The execution engine owns scan stages. This module owns building the
//! immutable scanner, backend acquisition, readiness and runtime inspection,
//! and the public entry methods that dispatch into the engine.

mod compile;
mod compile_helpers;
mod detector_digest;
mod runtime;
mod types;

pub use types::{
    CompiledScannerRuntime, GpuBackendAvailability, GpuBackendCandidateStatus, GpuInitPolicy,
};
pub(crate) use types::{GpuBackendAcquisitionFailure, GpuBackendPeers};

use crate::compiler::*;
#[cfg(feature = "simd")]
use crate::engine::build_simd_scanner;
use crate::engine::CompiledScanner;
#[cfg(all(test, feature = "simd"))]
use crate::engine::Phase2HsEngine;
use crate::engine::{
    build_confirmed_suffix_gate, derive_pattern_boundary_context, phase2, profile,
    require_selected_gpu_stack, ConfirmedAnchorIndex, CsrU32, Phase1Admission, Phase2AnchorIndex,
};
#[cfg(feature = "gpu")]
use crate::engine::{
    regex_match_byte_upper_bound, GpuResidentLiteralSlot, Phase2GpuDfaCatalogCache,
};
use crate::error::Result;
use crate::types::*;
use keyhog_core::{Chunk, DetectorSpec, RawMatch};
use std::sync::{Arc, OnceLock};

#[cfg(test)]
pub(crate) use runtime::Phase2PoolBreakdown;
