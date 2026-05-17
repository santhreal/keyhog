//! Device-loss classification and persistent-pipeline rebuild policy.

use std::sync::Arc;

use vyre_driver::backend::{CompiledPipeline, DispatchConfig, VyreBackend};
use vyre_driver::BackendError;
use vyre_foundation::ir::Program;

/// Recovery action taken after a backend device-loss symptom.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MegakernelRecoveryDecision {
    /// The runtime rebuilt the compiled pipeline on the same backend.
    RecompiledPipeline,
}

/// Runtime recovery policy for persistent megakernel dispatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MegakernelRecoveryPolicy {
    /// Retry a dispatch once after a device-loss-like backend error.
    pub retry_device_loss_once: bool,
}

impl Default for MegakernelRecoveryPolicy {
    fn default() -> Self {
        Self {
            retry_device_loss_once: true,
        }
    }
}

/// Return true when a backend error is consistent with device loss or a stale
/// compiled pipeline.
#[must_use]
pub fn backend_error_indicates_device_loss(error: &BackendError) -> bool {
    let text = error.to_string();
    DEVICE_LOSS_MARKERS
        .iter()
        .any(|marker| contains_ascii_case_insensitive(&text, marker))
}

const DEVICE_LOSS_MARKERS: &[&str] = &[
    "device lost",
    "devicelost",
    "context lost",
    "lost device",
    "adapter lost",
    "gpu reset",
    "device_error_context_is_destroyed",
    "device_error_context_is_current",
    "device_error_deinitialized",
    "stale pipeline",
];

fn contains_ascii_case_insensitive(haystack: &str, needle: &str) -> bool {
    let needle = needle.as_bytes();
    if needle.is_empty() {
        return true;
    }
    haystack
        .as_bytes()
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle))
}

/// Recompile a persistent megakernel pipeline after a recoverable device
/// failure.
///
/// # Errors
///
/// Returns the backend compile error if the backend cannot rebuild the program.
pub fn recover_compiled_pipeline(
    backend: &Arc<dyn VyreBackend>,
    program: Arc<Program>,
    config: &DispatchConfig,
) -> Result<Arc<dyn CompiledPipeline>, BackendError> {
    vyre_driver::pipeline::compile_shared(Arc::clone(backend), program, config)
}
