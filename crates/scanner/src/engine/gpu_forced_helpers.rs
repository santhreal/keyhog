#[cfg(test)]
use crate::hw_probe::ScanBackend;

#[cfg(test)]
use super::CompiledScanner;

#[cfg(feature = "gpu")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SelectedGpuDispatchError {
    reason: String,
}

#[cfg(feature = "gpu")]
impl SelectedGpuDispatchError {
    pub(crate) fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }

    pub(crate) fn reason(&self) -> &str {
        &self.reason
    }
}

#[cfg(feature = "gpu")]
impl std::fmt::Display for SelectedGpuDispatchError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.reason)
    }
}

#[cfg(feature = "gpu")]
impl std::error::Error for SelectedGpuDispatchError {}

#[cfg(test)]
/// Error message when routing forces GPU but the scanner cannot dispatch.
#[must_use]
pub(crate) fn gpu_forced_unavailable_message(
    scanner: &CompiledScanner,
    backend: ScanBackend,
) -> Option<String> {
    if !backend.is_gpu() {
        return None;
    }
    if scanner.gpu_stack_usable_for(backend) {
        return None;
    }
    Some(format!(
        "{} selected but GPU stack unavailable ({}, gpu_literals={}, gpu_matcher={}) - \
         silent CPU fallback is forbidden; repair this GPU driver and recalibrate autoroute, or explicitly choose `--backend simd-regex` or `--backend cpu-fallback`",
        backend.label(),
        scanner.gpu_backend_unavailable_reason(backend),
        scanner.gpu_literals.is_some(),
        scanner.gpu_matcher().is_some(),
    ))
}
