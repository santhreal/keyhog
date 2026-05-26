//! KH-GAP-002: explicit failure when `KEYHOG_BACKEND` forces GPU but stack unavailable.

use crate::hw_probe::{forced_backend_from_env, ScanBackend};

use super::CompiledScanner;

/// Error message when env forces GPU/MegaScan but the scanner cannot dispatch.
#[must_use]
pub fn gpu_forced_unavailable_message(
    scanner: &CompiledScanner,
    backend: ScanBackend,
) -> Option<String> {
    let forced = forced_backend_from_env()?;
    if !matches!(forced, ScanBackend::Gpu | ScanBackend::MegaScan) {
        return None;
    }
    if !matches!(backend, ScanBackend::Gpu | ScanBackend::MegaScan) {
        return None;
    }
    if scanner.gpu_stack_usable() {
        return None;
    }
    Some(format!(
        "KEYHOG_BACKEND={} but GPU stack unavailable (gpu_literals={}, gpu_backend={}, gpu_matcher={}) — \
         silent CPU fallback is forbidden; unset KEYHOG_BACKEND or install a compatible GPU adapter",
        forced.label(),
        scanner.gpu_literals.is_some(),
        scanner.gpu_backend.is_some(),
        scanner.gpu_matcher().is_some(),
    ))
}

/// Panic with an explicit message when env forces GPU and the stack is down.
pub fn deny_silent_gpu_degrade(scanner: &CompiledScanner, backend: ScanBackend) {
    if let Some(msg) = gpu_forced_unavailable_message(scanner, backend) {
        panic!("{msg}");
    }
}

impl CompiledScanner {
    /// True when literals, backend handle, and compiled matcher are all present.
    pub(crate) fn gpu_stack_usable(&self) -> bool {
        self.gpu_literals.is_some() && self.gpu_backend.is_some() && self.gpu_matcher().is_some()
    }
}
