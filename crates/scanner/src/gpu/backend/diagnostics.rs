//! Typed GPU diagnostics and explicit recovery receipts.
//!
//! This module never exits the process. Required-GPU failures travel as typed
//! errors to the scanner/CLI boundary; recall-safe CPU recovery emits a receipt
//! and increments the backend-local recovery counter.

use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};

#[derive(Debug)]
pub(super) struct GpuInitError {
    pub(super) adapter_present: bool,
    pub(super) detail: Box<dyn std::error::Error + Send + Sync>,
}

impl GpuInitError {
    pub(super) fn no_adapter(detail: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> Self {
        Self {
            adapter_present: false,
            detail: detail.into(),
        }
    }

    pub(super) fn adapter_unusable(
        detail: impl Into<Box<dyn std::error::Error + Send + Sync>>,
    ) -> Self {
        Self {
            adapter_present: true,
            detail: detail.into(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct GpuBackendError {
    detail: String,
}

impl GpuBackendError {
    pub(super) fn new(detail: impl Into<String>) -> Self {
        Self {
            detail: detail.into(),
        }
    }
}

impl fmt::Display for GpuBackendError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.detail)
    }
}

impl std::error::Error for GpuBackendError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum GpuInitFailureAction {
    RequiredFailure,
    RecoverWithReceipt,
    QuietAbsence,
}

pub(super) fn classify_gpu_init_failure(
    err: &GpuInitError,
    disabled: bool,
    required: bool,
) -> GpuInitFailureAction {
    if required {
        return GpuInitFailureAction::RequiredFailure;
    }
    if !disabled && err.adapter_present {
        return GpuInitFailureAction::RecoverWithReceipt;
    }
    GpuInitFailureAction::QuietAbsence
}

static MOE_RUNTIME_DEGRADE_WARNED: AtomicBool = AtomicBool::new(false);
static MOE_NONFINITE_WARNED: AtomicBool = AtomicBool::new(false);
static MOE_NUMERIC_DIVERGENCE_WARNED: AtomicBool = AtomicBool::new(false);
static MOE_BUFFER_POOL_POISON_WARNED: AtomicBool = AtomicBool::new(false);

pub(super) fn on_gpu_init_failed(
    err: &GpuInitError,
    disabled: bool,
    required: bool,
) -> Result<(), GpuBackendError> {
    match classify_gpu_init_failure(err, disabled, required) {
        GpuInitFailureAction::RequiredFailure => Err(GpuBackendError::new(format!(
            "--require-gpu requested but GPU MoE init failed: {}",
            err.detail
        ))),
        GpuInitFailureAction::RecoverWithReceipt => {
            crate::gpu::record_recovery_receipt();
            eprintln!(
                "keyhog: a GPU was detected but could not be initialized; using the \
CPU/SIMD scan path. Use --no-gpu to silence this, or --require-gpu to fail instead."
            );
            tracing::debug!(detail = %err.detail, "GPU MoE initialization recovery receipt emitted");
            Ok(())
        }
        GpuInitFailureAction::QuietAbsence => {
            tracing::debug!(detail = %err.detail, "GPU MoE initialization found no hardware adapter");
            Ok(())
        }
    }
}

pub(crate) fn moe_runtime_degrade(reason: &str) -> Result<(), GpuBackendError> {
    let no_gpu = crate::gpu::gpu_disabled_by_policy();
    if crate::gpu::gpu_required_by_policy() {
        return Err(GpuBackendError::new(format!(
            "--require-gpu requested but the GPU MoE dispatch failed at runtime \
({reason}). Refusing to silently degrade to the CPU MoE."
        )));
    }
    if no_gpu {
        return Ok(());
    }
    crate::gpu::record_recovery_receipt();
    tracing::warn!(
        reason,
        "GPU MoE dispatch failed at runtime; affected batches are scored on the CPU MoE"
    );
    if !MOE_RUNTIME_DEGRADE_WARNED.swap(true, Ordering::Relaxed) {
        eprintln!(
            "keyhog: GPU MoE dispatch failed at runtime ({reason}); affected batches in \
this scan are scored on the CPU MoE (identical scores, lower throughput). Set \
--no-gpu to silence, or --require-gpu to fail instead."
        );
    }
    Ok(())
}

pub(super) fn moe_nonfinite_degrade(nonfinite: usize, total: usize) -> Result<(), GpuBackendError> {
    if crate::gpu::gpu_required_by_policy() {
        return Err(GpuBackendError::new(format!(
            "--require-gpu requested but the GPU MoE returned {nonfinite}/{total} \
non-finite (NaN/Inf) confidence score(s), a GPU driver/shader/weights malfunction. \
Refusing to continue with an untrusted GPU score."
        )));
    }
    if crate::gpu::gpu_disabled_by_policy() {
        return Ok(());
    }
    crate::gpu::record_recovery_receipt();
    tracing::error!(
        nonfinite,
        total,
        "GPU MoE produced non-finite confidence scores; affected batch is routed to CPU MoE"
    );
    if !MOE_NONFINITE_WARNED.swap(true, Ordering::Relaxed) {
        eprintln!(
            "keyhog: GPU MoE produced {nonfinite}/{total} non-finite (NaN/Inf) confidence \
score(s); the complete batch is rescored by the CPU MoE and GPU MoE scoring is disabled \
for this process. This indicates a GPU driver/shader/weights bug worth investigating. \
Use --no-gpu to select CPU scoring explicitly, or --require-gpu to fail instead."
        );
    }
    Ok(())
}

pub(super) fn moe_numeric_divergence_degrade(reason: &str) -> Result<(), GpuBackendError> {
    if crate::gpu::gpu_required_by_policy() {
        return Err(GpuBackendError::new(format!(
            "--require-gpu requested but the GPU MoE failed the CPU parity probe ({reason}). \
Refusing to silently score confidence on the CPU MoE."
        )));
    }
    if crate::gpu::gpu_disabled_by_policy() {
        return Ok(());
    }
    crate::gpu::record_recovery_receipt();
    tracing::error!(
        reason,
        "GPU MoE parity probe diverged from CPU MoE; scoring batches on CPU"
    );
    if !MOE_NUMERIC_DIVERGENCE_WARNED.swap(true, Ordering::Relaxed) {
        eprintln!(
            "keyhog: GPU MoE parity probe failed ({reason}); confidence batches are scored on \
the CPU MoE instead. Use --require-gpu to fail until the GPU shader/driver/weights are fixed."
        );
    }
    Ok(())
}

pub(super) fn report_buffer_pool_poison_once() {
    if !MOE_BUFFER_POOL_POISON_WARNED.swap(true, Ordering::Relaxed) {
        tracing::warn!(
            "GPU MoE buffer pool lock was poisoned; recovering the reusable buffer state"
        );
    }
}
