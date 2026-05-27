//! KH-GAP-002: explicit failure when `KEYHOG_BACKEND` forces GPU but stack unavailable.
//!
//! Also: one-shot loud warning on runtime GPU dispatch failure that
//! degrades to CPU. The hardware probe + compile-time visibility
//! warnings can't catch the case where GPU acquisition succeeds but
//! a specific scan dispatch fails (vyre lowering rejecting a
//! program, CUDA driver returning a transient error, etc.). Per
//! the no-silent-fallback rule, the user needs to know the scan
//! didn't actually use the GPU they thought was active.

use crate::hw_probe::{forced_backend_from_env, ScanBackend};

use super::CompiledScanner;

/// Process-lifetime guard so the runtime-degrade warning fires once
/// per process, not once per scan or once per chunk.
static RUNTIME_DEGRADE_WARNED: std::sync::OnceLock<()> = std::sync::OnceLock::new();

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

/// Panic with an explicit message when env forces GPU and the stack
/// is down. Otherwise, when the scanner asked for GPU but is about
/// to degrade to CPU at runtime, emit a one-shot stderr warning so
/// the user sees the silent fallback they didn't ask for. Set
/// KEYHOG_NO_GPU=1 to silence the warning, or KEYHOG_REQUIRE_GPU=1
/// to exit (2) instead.
pub fn deny_silent_gpu_degrade(scanner: &CompiledScanner, backend: ScanBackend) {
    if let Some(msg) = gpu_forced_unavailable_message(scanner, backend) {
        panic!("{msg}");
    }
    if !matches!(backend, ScanBackend::Gpu | ScanBackend::MegaScan) {
        return;
    }
    let no_gpu = std::env::var("KEYHOG_NO_GPU").as_deref() == Ok("1");
    let require_gpu = std::env::var("KEYHOG_REQUIRE_GPU").as_deref() == Ok("1");
    if require_gpu {
        eprintln!(
            "keyhog: KEYHOG_REQUIRE_GPU=1 but the GPU dispatch failed at runtime \
(literals={}, backend={}, matcher={}). Refusing to silently degrade.",
            scanner.gpu_literals.is_some(),
            scanner.gpu_backend.is_some(),
            scanner.gpu_matcher().is_some(),
        );
        std::process::exit(2);
    }
    if no_gpu {
        return;
    }
    if RUNTIME_DEGRADE_WARNED.set(()).is_ok() {
        eprintln!(
            "keyhog: GPU dispatch failed at runtime; this scan and any subsequent \
ones in this process degrade to CPU/SIMD. Often a transient driver issue or a \
program the GPU lowering pipeline rejects (check the preceding tracing::error \
line for the underlying message). Set KEYHOG_NO_GPU=1 to silence, or \
KEYHOG_REQUIRE_GPU=1 to hard-fail next time."
        );
    }
}

impl CompiledScanner {
    /// True when literals, backend handle, and compiled matcher are all present.
    pub(crate) fn gpu_stack_usable(&self) -> bool {
        self.gpu_literals.is_some() && self.gpu_backend.is_some() && self.gpu_matcher().is_some()
    }
}
